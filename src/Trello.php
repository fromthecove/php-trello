<?php
/**
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is “Incompatible With Secondary Licenses”,
 * as defined by the Mozilla Public License, v. 2.0.
 */

namespace Trello;

use Trello\OAuthSimple;

/**
 * Trello
 * This is a basic Trello PHP wrapper that is used very similar to the Trello-made client.js
 * library.  The method calls are the same (ie: Trello->post() or Trello->boards->get()).  See
 * https://trello.com/docs/gettingstarted/clientjs.html for detailed information.
 *
 * Some differences - you cannot specify callbacks for success or error.  If they're requested
 * I may add them in, but it's not really my style to pass callbacks like that around PHP when
 * I can simply return the data instead.
 *
 * Trello::authorize here does OAuth authentication, so you must pass your Secret Key to the
 * constructor or set it after instantiation before calling the authorize method.  Some parameters
 * are the same as client.js (name, scope, expiration) and there is one extra (redirect_uri) for
 * the OAuth callback.
 *
 * Go to https://trello.com/1/appKey/generate to get your API and OAuth keys
 *
 * @author    Matt Zuba <matt.zuba@gmail.com>
 * @author    Daniel Lowhorn <dlowhorn@gmail.com>
 * @copyright 2013 Matt Zuba
 * @package   php-trello
 */
class Trello {

    /**
     * php-trello version
     */
    private $version = '1.1.1';

    /**
     * Trello API Version
     */
    protected $apiVersion = 1;

    /**
     * Trello API Endpoint
     */
    protected $apiEndpoint = 'https://api.trello.com';

    /**
     * Trello Auth endpoint
     */
    protected $authEndpoint = 'https://trello.com';

    /**
     * Populated on instantiation, combo of apiEndpoint and apiVersion
     */
    protected $baseUrl;

    /**
     * Consumer key from Trello API
     */
    protected $consumer_key;

    /**
     * OAuth Secret Key
     */
    protected $shared_secret;

    /**
     * Non-OAuth or OAuth token
     */
    protected $token;

    /**
     * OAuth Secret token
     */
    protected $oauth_secret;

    /**
     * Last error encountered by REST api
     */
    protected $lastError;

    /**
     * __construct
     *
     * @param string $consumer_key
     * @param string $token         [optional]
     * @param string $shared_secret [optional]
     * @param string $oauth_secret  [optional]
     *
     * @throws \Exception
     */
    public function __construct($consumer_key, $shared_secret = null, $token = null, $oauth_secret = null)
    {

        // CURL is required in order for this extension to work
        if (!function_exists('curl_init')) {
            throw new \Exception('CURL is required for php-trello');
        }

        // Sessions are used to for OAuth
        if (session_id() === '' && !headers_sent()) {
            session_start();
        }

        $this->baseUrl       = "$this->apiEndpoint/$this->apiVersion/";
        $this->consumer_key  = $consumer_key;
        $this->shared_secret = $shared_secret;
        $this->token         = $token;
        $this->oauth_secret  = $oauth_secret;
    }

    /**
     * version
     *
     * @return int Trello API version
     */
    public function version()
    {
        return $this->apiVersion;
    }

    /**
     * key
     *
     * @return string
     */
    public function key()
    {
        return $this->consumer_key;
    }

    /**
     * setKey
     *
     * @param string $consumer_key
     */
    public function setKey($consumer_key)
    {
        $this->consumer_key = $consumer_key;
    }

    /**
     * token
     *
     * @return string
     */
    public function token()
    {
        return $this->token;
    }

    /**
     * setToken
     *
     * @param string $token
     */
    public function setToken($token)
    {
        $this->token = $token;
    }

    /**
     * oauthSecret
     *
     * @return string
     */
    public function oauthSecret()
    {
        return $this->oauth_secret;
    }

    /**
     * setOauthSecret
     *
     * @param string $secret
     */
    public function setOauthSecret($secret)
    {
        $this->oauth_secret = $secret;
    }

    /**
     * authorized
     *
     * @return boolean
     */
    public function authorized()
    {
        return $this->token != null;
    }

    /**
     * error
     *
     * @return string
     */
    public function error()
    {
        return $this->lastError;
    }

    /**
     * authorize
     * Performs an OAuth authorization to Trello.  Possible options include:
     * name - Application name as the user see's it
     * redirect_uri - where should the OAuth request direct it's response
     * expiration - how long will the token be good for
     * scope - what you will need access to
     *
     * @param array   $userOptions
     * @param boolean $return
     *
     * @return boolean|void
     */
    public function authorize($userOptions = array(), $return = FALSE)
    {
        if ($this->authorized()) {
            return TRUE;
        }

        if (!$this->shared_secret) {
            return FALSE;
        }

        $oauth = new OAuthSimple($this->consumer_key, $this->shared_secret);

        // We're back from an authorization request, process it
        if (isset($_GET['oauth_verifier'], $_SESSION['oauth_token_secret'])) {

            // $_SESSION[oauth_token_secret] was stored before the Authorization redirect
            $signatures = array(
                'oauth_secret' => $_SESSION['oauth_token_secret'],
                'oauth_token'  => $_GET['oauth_token'],
            );

            $request = $oauth->sign(array(
                'path'       => "$this->authEndpoint/$this->apiVersion/OAuthGetAccessToken",
                'parameters' => array(
                    'oauth_verifier' => $_GET['oauth_verifier'],
                    'oauth_token'    => $_GET['oauth_token'],
                ),
                'signatures' => $signatures,
            ));

            // Initiate our request to get a permanent access token
            $ch = curl_init($request['signed_url']);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
            $result = curl_exec($ch);

            // Parse our tokens and store them
            parse_str($result, $returned_items);
            $this->token        = $returned_items['oauth_token'];
            $this->oauth_secret = $returned_items['oauth_token_secret'];

            // To prevent a refresh of the page from working to re-do this step, clear out the temp
            // access token.
            unset($_SESSION['oauth_token_secret']);

            return TRUE;
        }

        $options = array_merge(array(
            'name'         => null,
            'redirect_uri' => $this->callbackUri(),
            'expiration'   => '30days',
            'scope'        => array(
                'read'    => TRUE,
                'write'   => FALSE,
                'account' => FALSE,
            ),
        ), $userOptions);

        $scope = implode(',', array_keys(array_filter($options['scope'])));

        // Get a request token from Trello
        $request = $oauth->sign(array(
            'path'       => "$this->authEndpoint/$this->apiVersion/OAuthGetRequestToken",
            'parameters' => array(
                'oauth_callback' => $options['redirect_uri'],
            ),
        ));

        $ch = curl_init($request['signed_url']);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
        $result = curl_exec($ch);

        // We store the token_secret for later because it's needed to get a permanent one
        parse_str($result, $returned_items);
        $request_token                  = $returned_items['oauth_token'];
        $_SESSION['oauth_token_secret'] = $returned_items['oauth_token_secret'];

        // Create and process a request with all of our options for Authorization
        $request = $oauth->sign(array(
            'path'       => "$this->authEndpoint/$this->apiVersion/OAuthAuthorizeToken",
            'parameters' => array(
                'oauth_token' => $request_token,
                'name'        => $options['name'],
                'expiration'  => $options['expiration'],
                'scope'       => $scope,
            ),
        ));

        if ($return) {
            return $request['signed_url'];
        }

        header("Location: $request[signed_url]");
        exit;
    }

    /**
     * __call
     * We use PHP's magic __call method for dynamic calling of the REST types.
     *
     * @param string $method
     * @param array  $arguments
     *
     * @return mixed array of stdClass objects or false on failure
     * @throws \Exception
     */
    public function __call($method, $arguments)
    {
        if (in_array($method, array('get', 'post', 'put', 'delete', 'del'))) {
            array_unshift($arguments, strtoupper($method));

            return call_user_func_array(array($this, 'rest'), $arguments);
        }

        throw new \Exception("Method $method does not exist.");
    }

    /**
     * __get
     * This is used as a shortcut for the types of collections.
     *
     * @param string $collection
     *
     * @return \Trello\Collection
     * @throws \Exception
     */
    public function __get($collection)
    {
        return new Collection($collection, $this);
    }

    /**
     * rest
     * This method actually performs the calls back to the Trello REST service
     *
     * @param string $method
     *
     * @return mixed array of stdClass objects or false on failure
     * @throws \Exception
     */
    public function rest($method)
    {
        $args = array_slice(func_get_args(), 1);
        extract($this->parseRestArgs($args)); /* path, params */

        $restData = array();
        if ($this->consumer_key && !$this->shared_secret) {
            $restData['key'] = $this->consumer_key;
        }
        if ($this->token && !$this->shared_secret) {
            $restData['token'] = $this->token;
        }

        if (isset($params) && is_array($params)) {
            $restData = array_merge($restData, $params);
        }

        // Perform the CURL query
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($ch, CURLOPT_USERAGENT, "php-trello/$this->version");
        curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);

        switch ($method) {
            case 'GET':
            break;
            case 'POST':
                curl_setopt($ch, CURLOPT_POST, TRUE);
                curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($restData, '', '&'));
                $restData = array();
            break;
            case 'PUT':
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
                curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($restData, '', '&'));
                $restData = array();
            break;
            case 'DELETE':
            case 'DEL':
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
            break;
            default:
                throw new \Exception('Invalid method specified');
        }

        $headers = null;
        $url     = $this->buildRequestUrl($method, $path, $restData, $headers);
        curl_setopt($ch, CURLOPT_URL, $url);

        if ($headers !== null) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, is_array($headers) ? $headers : array($headers));
        }

        // Grab the response from Trello
        $responseBody = curl_exec($ch);
        if (!$responseBody) {

            // If there was a CURL error of some sort, log it and return false
            $this->lastError = curl_error($ch);

            return FALSE;
        }

        $responseCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $responseBody = trim($responseBody);
        if (strpos($responseCode, '2') !== 0) {

            // If we didn't get a 2xx HTTP response from Trello, log the responsebody as an error
            $this->lastError = $responseBody;

            return FALSE;
        }

        $this->lastError = '';

        return json_decode($responseBody);
    }

    /**
     * buildRequestUrl
     * Parse arguments sent to the rest function.  Might be extended in future for callbacks.
     *
     * @param string $method
     * @param string $path
     * @param array  $data
     * @param mixed  $headers
     *
     * @return string
     */
    public function buildRequestUrl($method, $path, $data, &$headers)
    {

        $baseUrl = $finalUrl = "{$this->baseUrl}{$path}";

        // These methods require the data appended to the URL
        if (in_array($method, array('GET', 'DELETE', 'DEL')) && !empty($data)) {
            $finalUrl .= '?' . http_build_query($data, '', '&');
        }

        //
        // If we're using oauth, account for it, using header authentication (Trello disabled param-based oauth March 31, 2021)
        if ($this->canOauth()) {

            $oauth = new OAuthSimple($this->consumer_key, $this->shared_secret);
            $oauth
                ->setTokensAndSecrets(array('access_token' => $this->token, 'access_secret' => $this->oauth_secret,))
                ->setParameters()
            ;

            $request = $oauth->sign(array('path' => $baseUrl));
            $headers = 'Authorization: ' . $request['header'];

        }

        return $finalUrl;

    }

    /**
     * parseRestArgs
     * Parse arguments sent to the rest function.  Might be extended in future for callbacks.
     *
     * @param array $args
     *
     * @return array
     */
    protected function parseRestArgs($args)
    {
        $opts = array(
            'path'   => '',
            'params' => array(),
        );

        if (!empty($args[0])) {
            $opts['path'] = $args[0];
        }
        if (!empty($args[1])) {
            $opts['params'] = $args[1];
        }

        return $opts;
    }

    /**
     * canOauth
     * Determines if we can use OAuth for our REST request
     *
     * @return boolean
     */
    protected function canOauth()
    {
        return $this->consumer_key && $this->token && $this->shared_secret && $this->oauth_secret;
    }

    /**
     * callbackUri
     * Returns the currently loaded PHP page to be used as the callback_url if one isn't supplied
     *
     * @return string
     */
    protected function callbackUri()
    {
        if (empty($_SERVER['REQUEST_URI'])) {
            return '';
        }
        $port     = $_SERVER['SERVER_PORT'] == '80' || $_SERVER['SERVER_PORT'] == '443' ? '' : ":$_SERVER[SERVER_PORT]";
        $protocol = 'http' . (!empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) != 'off' ? 's://' : '://');

        return "{$protocol}{$_SERVER['HTTP_HOST']}{$port}{$_SERVER['REQUEST_URI']}";
    }

}
