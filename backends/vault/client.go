package vault

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/kelseyhightower/confd/log"
)

// Client is a wrapper around the vault client
type Client struct {
	client *vaultapi.Client
}

// get a
func getParameter(key string, parameters map[string]string) string {
	value := parameters[key]
	if value == "" {
		// panic if a configuration is missing
		panic(fmt.Sprintf("%s is missing from configuration", key))
	}
	return value
}

// panicToError converts a panic to an error
func panicToError(err *error) {
	if r := recover(); r != nil {
		switch t := r.(type) {
		case string:
			*err = errors.New(t)
		case error:
			*err = t
		default: // panic again if we don't know how to handle
			panic(r)
		}
	}
}

// authenticate with the remote client
func authenticate(c *vaultapi.Client, authType string, params map[string]string) (err error) {
	var secret *vaultapi.Secret

	// handle panics gracefully by creating an error
	// this would happen when we get a parameter that is missing
	defer panicToError(&err)

	path := params["path"]
	if path == "" {
		path = authType
		if authType == "app-role" {
			path = "approle"
		}
	}
	url := fmt.Sprintf("/auth/%s/login", path)

	switch authType {
	case "app-role":
		secret, err = c.Logical().Write(url, map[string]interface{}{
			"role_id":   getParameter("role-id", params),
			"secret_id": getParameter("secret-id", params),
		})
	case "app-id":
		secret, err = c.Logical().Write(url, map[string]interface{}{
			"app_id":  getParameter("app-id", params),
			"user_id": getParameter("user-id", params),
		})
	case "github":
		secret, err = c.Logical().Write(url, map[string]interface{}{
			"token": getParameter("token", params),
		})
	case "token":
		c.SetToken(getParameter("token", params))
		secret, err = c.Logical().Read("/auth/token/lookup-self")
	case "userpass":
		username, password := getParameter("username", params), getParameter("password", params)
		secret, err = c.Logical().Write(fmt.Sprintf("%s/%s", url, username), map[string]interface{}{
			"password": password,
		})
	case "kubernetes":
		jwt, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
		if err != nil {
			return err
		}
		secret, err = c.Logical().Write(url, map[string]interface{}{
			"jwt":  string(jwt[:]),
			"role": getParameter("role-id", params),
		})
	case "cert":
		secret, err = c.Logical().Write(url, map[string]interface{}{})
	}

	if err != nil {
		return err
	}

	// if the token has already been set
	if c.Token() != "" {
		return nil
	}

	if secret == nil || secret.Auth == nil {
		return errors.New("Unable to authenticate")
	}

	log.Debug("client authenticated with auth backend: %s", authType)
	// the default place for a token is in the auth section
	// otherwise, the backend will set the token itself
	c.SetToken(secret.Auth.ClientToken)
	return nil
}

func getConfig(address, cert, key, caCert string) (*vaultapi.Config, error) {
	conf := vaultapi.DefaultConfig()
	conf.Address = address

	tlsConfig := &tls.Config{}
	if cert != "" && key != "" {
		clientCert, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{clientCert}
		tlsConfig.BuildNameToCertificate()
	}

	if caCert != "" {
		ca, err := ioutil.ReadFile(caCert)
		if err != nil {
			return nil, err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(ca)
		tlsConfig.RootCAs = caCertPool
	}

	conf.HttpClient.Transport = &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return conf, nil
}

// New returns an *vault.Client with a connection to named machines.
// It returns an error if a connection to the cluster cannot be made.
func New(address, authType string, params map[string]string) (*Client, error) {
	if authType == "" {
		return nil, errors.New("you have to set the auth type when using the vault backend")
	}
	log.Info("Vault authentication backend set to %s", authType)
	conf, err := getConfig(address, params["cert"], params["key"], params["caCert"])

	if err != nil {
		return nil, err
	}

	c, err := vaultapi.NewClient(conf)
	if err != nil {
		return nil, err
	}

	if err := authenticate(c, authType, params); err != nil {
		return nil, err
	}
	return &Client{c}, nil
}

// GetValues queries etcd for keys prefixed by prefix.
func (c *Client) GetValues(keys []string) (map[string]string, error) {
	branches := make(map[string]bool)
	for _, key := range keys {
		walkTree(c, key, branches)
	}
	vars := make(map[string]string)
	for key := range branches {
		log.Debug("getting %s from vault", key)
		mountPath, v2, pathError := isKVv2(key, c.client)
		if pathError != nil {
			log.Debug("Error checking version %s: %s", key, pathError)
			return nil, pathError
		}

		versionParam := map[string]string{} // Always get latest version

		kvpath := key
		if v2 {
			kvpath = sanitizePath(kvpath)
			kvpath = addPrefixToVKVPath(kvpath, mountPath, "data")
			log.Debug("Prefix added to the kv path %v", kvpath)
		}

		resp, err := kvReadRequest(c.client, kvpath, versionParam)

		if err != nil {
			log.Debug("there was an error extracting %s", key)
			return nil, err
		}
		if resp == nil || resp.Data == nil {
			log.Debug("Response is empty or no data for key %s", key)
			continue
		}

		data := resp.Data
		if v2 && data != nil {
			data = nil
			dataRaw := resp.Data["data"]
			if dataRaw != nil {
				data = dataRaw.(map[string]interface{})
			}
		}
		// if the key has only one string value
		// treat it as a string and not a map of values
		if val, ok := isKV(data); ok {
			vars[key] = val
		} else {
			// save the json encoded response
			// and flatten it to allow usage of gets & getvs
			js, _ := json.Marshal(data)
			vars[key] = string(js)
			flatten(key, data, vars)
		}
	}
	return vars, nil
}

// isKV checks if a given map has only one key of type string
// if so, returns the value of that key
func isKV(data map[string]interface{}) (string, bool) {
	if len(data) == 1 {
		if value, ok := data["value"]; ok {
			if text, ok := value.(string); ok {
				return text, true
			}
		}
	}
	return "", false
}

// recursively walks on all the values of a specific key and set them in the variables map
func flatten(key string, value interface{}, vars map[string]string) {
	switch value.(type) {
	case string:
		log.Debug("setting key %s to: %s", key, value)
		vars[key] = value.(string)
	case map[string]interface{}:
		inner := value.(map[string]interface{})
		for innerKey, innerValue := range inner {
			innerKey = path.Join(key, "/", innerKey)
			flatten(innerKey, innerValue, vars)
		}
	default: // we don't know how to handle non string or maps of strings
		log.Warning("type of '%s' is not supported (%T)", key, value)
	}
}

// recursively walk the branches in the Vault, adding to branches map
func walkTree(c *Client, key string, branches map[string]bool) error {
	log.Debug("listing %s from vault", key)

	// strip trailing slash as long as it's not the only character
	if last := len(key) - 1; last > 0 && key[last] == '/' {
		key = key[:last]
	}
	if branches[key] {
		// already processed this branch
		log.Debug("already processed this branch %s", key)
		return nil
	}
	branches[key] = true

	mountPath, v2, pathError := isKVv2(key, c.client)
	if pathError != nil {
		log.Debug("there was an error extracting %s %s", key, pathError.Error())
		return pathError
	}

	kvpath := key
	if v2 {
		kvpath = ensureTrailingSlash(sanitizePath(kvpath))
		kvpath = addPrefixToVKVPath(kvpath, mountPath, "metadata")
	}

	resp, err := c.client.Logical().List(kvpath)

	if err != nil {
		log.Debug("there was an error extracting %s", key)
		return err
	}
	if resp == nil || resp.Data == nil || resp.Data["keys"] == nil {
		log.Debug("Empty list for key %s", key)
		return nil
	}

	switch resp.Data["keys"].(type) {
	case []interface{}:
		// expected
	default:
		log.Warning("key list type of '%s' is not supported (%T)", key, resp.Data["keys"])
		return nil
	}

	keyList := resp.Data["keys"].([]interface{})
	for _, innerKey := range keyList {
		switch innerKey.(type) {

		case string:
			innerKey = path.Join(key, "/", innerKey.(string))
			walkTree(c, innerKey.(string), branches)

		default: // we don't know how to handle other data types
			log.Warning("type of '%s' is not supported (%T)", key, keyList)
		}
	}
	return nil
}

// WatchPrefix - not implemented at the moment
func (c *Client) WatchPrefix(prefix string, keys []string, waitIndex uint64, stopChan chan bool) (uint64, error) {
	<-stopChan
	return 0, nil
}

func kvPreflightVersionRequest(client *vaultapi.Client, path string) (string, int, error) {
	// We don't want to use a wrapping call here so save any custom value and
	// restore after
	currentWrappingLookupFunc := client.CurrentWrappingLookupFunc()
	client.SetWrappingLookupFunc(nil)
	defer client.SetWrappingLookupFunc(currentWrappingLookupFunc)
	currentOutputCurlString := client.OutputCurlString()
	client.SetOutputCurlString(false)
	defer client.SetOutputCurlString(currentOutputCurlString)

	r := client.NewRequest("GET", "/v1/sys/internal/ui/mounts/"+path)
	resp, err := client.RawRequest(r)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		// If we get a 404 we are using an older version of vault, default to
		// version 1
		if resp != nil && resp.StatusCode == 404 {
			return "", 1, nil
		}

		return "", 0, err
	}

	secret, err := vaultapi.ParseSecret(resp.Body)
	if err != nil {
		return "", 0, err
	}
	var mountPath string
	if mountPathRaw, ok := secret.Data["path"]; ok {
		mountPath = mountPathRaw.(string)
	}
	options := secret.Data["options"]
	if options == nil {
		return mountPath, 1, nil
	}
	versionRaw := options.(map[string]interface{})["version"]
	if versionRaw == nil {
		return mountPath, 1, nil
	}
	version := versionRaw.(string)
	switch version {
	case "", "1":
		return mountPath, 1, nil
	case "2":
		return mountPath, 2, nil
	}

	return mountPath, 1, nil
}

func isKVv2(path string, client *vaultapi.Client) (string, bool, error) {
	mountPath, version, err := kvPreflightVersionRequest(client, path)
	if err != nil {
		return "", false, err
	}

	return mountPath, version == 2, nil
}

func addPrefixToVKVPath(p, mountPath, apiPrefix string) string {
	switch {
	case p == mountPath, p == strings.TrimSuffix(mountPath, "/"):
		return path.Join(mountPath, apiPrefix)
	default:
		p = strings.TrimPrefix(p, mountPath)
		return path.Join(mountPath, apiPrefix, p)
	}
}

func kvReadRequest(client *vaultapi.Client, path string, params map[string]string) (*vaultapi.Secret, error) {
	r := client.NewRequest("GET", "/v1/"+path)
	for k, v := range params {
		r.Params.Set(k, v)
	}
	resp, err := client.RawRequest(r)
	if resp != nil {
		defer resp.Body.Close()
	}
	if resp != nil && resp.StatusCode == 404 {
		secret, parseErr := vaultapi.ParseSecret(resp.Body)
		switch parseErr {
		case nil:
		case io.EOF:
			return nil, nil
		default:
			return nil, parseErr
		}
		if secret != nil && (len(secret.Warnings) > 0 || len(secret.Data) > 0) {
			return secret, nil
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return vaultapi.ParseSecret(resp.Body)
}

// sanitizePath removes any leading or trailing things from a "path".
func sanitizePath(s string) string {
	return ensureNoTrailingSlash(ensureNoLeadingSlash(strings.TrimSpace(s)))
}

// ensureTrailingSlash ensures the given string has a trailing slash.
func ensureTrailingSlash(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	for len(s) > 0 && s[len(s)-1] != '/' {
		s = s + "/"
	}
	return s
}

// ensureNoTrailingSlash ensures the given string has a trailing slash.
func ensureNoTrailingSlash(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

// ensureNoLeadingSlash ensures the given string has a trailing slash.
func ensureNoLeadingSlash(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	for len(s) > 0 && s[0] == '/' {
		s = s[1:]
	}
	return s
}
