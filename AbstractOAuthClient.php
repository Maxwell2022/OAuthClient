<?php

namespace Maxwell\OAuthClient;

use Psr\Log\LoggerInterface;

abstract class AbstractOAuthClient
{
    const REQUEST_TIMEOUT = 30;
    const CONNECT_TIMEOUT = 30;
    const SSL_VERIFY_PEER = false;
    const DEFAULT_FORMAT = 'json';
    const USER_AGENT = 'Maxwell OAuthClient v1.0';

    /**
     * @var string Consumer key (client id)
     */
    protected $consumerKey;

    /**
     * @var string Consumer secret (client secret)
     */
    protected $consumerSecret;

    /**
     * @var string Application OAuth Token
     */
    protected $appOAuthToken;

    /**
     * @var string Application OAuth secret
     */
    protected $appTokenSecret;

    /**
     * @var string Redirect URL of the authentication
     */
    protected $redirectURI;

    /**
     * @var string User OAuth Token
     */
    protected $currentOAuthToken;

    /**
     * @var string User OAuth secret
     */
    protected $currentOAuthTokenSecret;

    /**
     * @var LoggerInterface Logger
     */
    protected $logger;

    /**
     * @var string Temporary path to perform file actions
     */
    protected $tmp;

    /**
     * @var string Last post id created
     */
    protected $lastPostId;

    /**
     * @var mixed OAuth Token object
     */
    protected $token;

    /**
     * @var mixed OAuth signature object
     */
    protected $sha1_method;

    /**
     * @var array list of headers
     */
    protected $http_header;

    /**
     * @var string HTTP code returned by curl
     */
    protected $http_code;

    /**
     * @var string HTTP info returned by curl
     */
    protected $http_info;

    /**
     * @var string Last URL called by curl
     */
    protected $http_url;

    /**
     * @param $consumer_key
     * @param $consumer_secret
     * @param $redirectURI
     * @param null $oauth_token
     * @param null $oauth_token_secret
     */
    function __construct($consumer_key, $consumer_secret, $redirectURI, $oauth_token = null, $oauth_token_secret = null)
    {
        $this->clientId = $consumer_key;
        $this->clientSecret = $consumer_secret;
        $this->redirectURI = $redirectURI;

        $this->consumer = new OAuth\Consumer($consumer_key, $consumer_secret, $redirectURI);
        $this->sha1_method = new OAuth\SignatureMethodHMAC();
    }

    /**
     * @param string $appOAuthToken
     */
    public function setAppOAuthToken($appOAuthToken)
    {
        $this->appOAuthToken = $appOAuthToken;
    }

    /**
     * @return string
     */
    public function getAppOAuthToken()
    {
        return $this->appOAuthToken;
    }

    /**
     * @param string $appTokenSecret
     */
    public function setAppTokenSecret($appTokenSecret)
    {
        $this->appTokenSecret = $appTokenSecret;
    }

    /**
     * @return string
     */
    public function getAppTokenSecret()
    {
        return $this->appTokenSecret;
    }

    /**
     * @param string $consumerKey
     */
    public function setConsumerKey($consumerKey)
    {
        $this->consumerKey = $consumerKey;
    }

    /**
     * @return string
     */
    public function getConsumerKey()
    {
        return $this->consumerKey;
    }

    /**
     * @param string $consumerSecret
     */
    public function setConsumerSecret($consumerSecret)
    {
        $this->consumerSecret = $consumerSecret;
    }

    /**
     * @return string
     */
    public function getConsumerSecret()
    {
        return $this->consumerSecret;
    }

    /**
     * @param \Psr\Log\LoggerInterface $logger
     */
    public function setLogger($logger)
    {
        $this->logger = $logger;
    }

    /**
     * @return \Psr\Log\LoggerInterface
     */
    public function getLogger()
    {
        return $this->logger;
    }

    /**
     * @param string $tmp
     */
    public function setTmp($tmp)
    {
        $this->tmp = $tmp;
    }

    /**
     * @return string
     */
    public function getTmp()
    {
        return $this->tmp;
    }

    /**
     * @param string $lastPostId
     */
    public function setLastPostId($lastPostId)
    {
        $this->lastPostId = $lastPostId;
    }

    /**
     * @return string
     */
    public function getLastPostId()
    {
        return $this->lastPostId;
    }

    /**
     * @param string $currentOAuthToken
     */
    public function setCurrentOAuthToken($currentOAuthToken)
    {
        $this->currentOAuthToken = $currentOAuthToken;
    }

    /**
     * @return string
     */
    public function getCurrentOAuthToken()
    {
        return $this->currentOAuthToken;
    }

    /**
     * @param string $currentOAuthTokenSecret
     */
    public function setCurrentOAuthTokenSecret($currentOAuthTokenSecret)
    {
        $this->currentOAuthTokenSecret = $currentOAuthTokenSecret;
    }

    /**
     * @return string
     */
    public function getCurrentOAuthTokenSecret()
    {
        return $this->currentOAuthTokenSecret;
    }

    /**
     * @param string $redirectURI
     */
    public function setRedirectURI($redirectURI)
    {
        $this->redirectURI = $redirectURI;
    }

    /**
     * Return the Authorize URL to redirect the user to
     *
     * @param null $redirectURI
     * @param null $scope
     * @param null $state
     * @param string $responseType
     * @return mixed
     */
    public abstract function getAuthorizeURL($redirectURI=null, $scope=null, $state=null, $responseType='code');

    /**
     * Exchange the code return by the authorisation with an access token
     *
     * @param $code
     * @param null $redirectURI
     * @return mixed
     */
    public abstract function getAccessToken($code, $redirectURI=null);

    /**
     * Publish a content on Social network
     *
     * @param $data
     * @return bool|void
     * @throws \Exception
     */
    public abstract function publish($data);

    public abstract function request($uri, $method='GET', $parameters=array());

    /**
     * Perform a GET request
     *
     * @param $uri
     * @param array $parameters
     * @return mixed
     */
    public function get($uri, $parameters=array())
    {
        return $this->request($uri, 'GET', $parameters);
    }

    /**
     * Perform a POST request
     *
     * @param $uri
     * @param array $parameters
     * @return mixed
     */
    public function post($uri, $parameters=array())
    {
        return $this->request($uri, 'POST', $parameters);
    }

    /**
     * Perform a DELETE request
     *
     * @param $uri
     * @param array $parameters
     * @return mixed
     */
    public function delete($uri, $parameters=array())
    {
        return $this->request($uri, 'DELETE', $parameters);
    }

    /**
     * @param null $uri
     * @return string
     */
    protected function getRedirectUri($uri = null)
    {
        $redirectURI = $this->redirectURI;

        if (null !== $uri) {
            $redirectURI = $uri;
        }

        if (!preg_match('#^http#i', $redirectURI)) {
            $protocol = 'http://';
            if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == 'on') {
                $protocol = 'https://';
            }
            $redirectURI = $protocol . $_SERVER['HTTP_HOST'] . $redirectURI;
        }

        return $redirectURI;
    }

    /**
     * Send a signed request using OAuth token
     *
     * @param $url
     * @param $method
     * @param $parameters
     * @return mixed
     */
    public function oAuthRequest($url, $method, $parameters)
    {
        if (strrpos($url, 'https://') !== 0 && strrpos($url, 'http://') !== 0) {
            $url = self::API_ENTRY_POINT.$url;
        }

        $request = OAuth\Request::from_consumer_and_token($this->getConsumerKey(), $this->getCurrentOAuthToken(), $method, $url, $parameters);
        $request->sign_request($this->sha1_method, $this->getConsumerKey(), $this->getCurrentOAuthToken());
        switch ($method) {
            case 'GET':
                return $this->http($request->to_url(), 'GET');
            default:
                return $this->http($request->get_normalized_http_url(), $method, $request->to_postdata());
        }
    }

    /**
     * Make an HTTP request
     *
     * @param $url
     * @param $method
     * @param null $postfields
     * @return mixed
     */
    function http($url, $method, $postfields = null)
    {
        $this->http_info = array();
        $ci = curl_init();
        /* Curl settings */
        curl_setopt($ci, CURLOPT_USERAGENT, self::USER_AGENT);
        curl_setopt($ci, CURLOPT_CONNECTTIMEOUT, self::CONNECT_TIMEOUT);
        curl_setopt($ci, CURLOPT_TIMEOUT, self::REQUEST_TIMEOUT);
        curl_setopt($ci, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ci, CURLOPT_HTTPHEADER, array('Expect:'));
        curl_setopt($ci, CURLOPT_SSL_VERIFYPEER, self::SSL_VERIFY_PEER);
        curl_setopt($ci, CURLOPT_HEADERFUNCTION, array($this, 'getHeader'));
        curl_setopt($ci, CURLOPT_HEADER, false);

        switch ($method) {
            case 'POST':
                curl_setopt($ci, CURLOPT_POST, true);
                if (!empty($postfields)) {
                    curl_setopt($ci, CURLOPT_POSTFIELDS, $postfields);
                }
                break;
            case 'DELETE':
                curl_setopt($ci, CURLOPT_CUSTOMREQUEST, 'DELETE');
                if (!empty($postfields)) {
                    $url = "{$url}?{$postfields}";
                }
        }

        curl_setopt($ci, CURLOPT_URL, $url);
        $response = curl_exec($ci);
        $this->http_code = curl_getinfo($ci, CURLINFO_HTTP_CODE);
        $this->http_info = array_merge($this->http_info, curl_getinfo($ci));
        $this->http_url = $url;
        curl_close($ci);

        return $response;
    }

    /**
     * Get the header info to store.
     *
     * @param $ch
     * @param $header
     * @return int
     */
    protected function getHeader($ch, $header)
    {
        $i = strpos($header, ':');
        $this->http_header = array();
        if (!empty($i)) {
            $key = str_replace('-', '_', strtolower(substr($header, 0, $i)));
            $value = trim(substr($header, $i + 2));
            $this->http_header[$key] = $value;
        }

        return strlen($header);
    }

    /**
     * @param  $oauth_token
     * @param  $oauth_token_secret
     * @return void
     */
    public function setOAuthToken($oauth_token, $oauth_token_secret)
    {
        $this->token = new OAuth\Consumer($oauth_token, $oauth_token_secret);
    }

    /**
     * Avoid the notices if the token is not set
     *
     * @param  $request
     * @return array
     */
    function getOAuthToken($request)
    {
        $token = OAuth\Util::parse_parameters($request);
        if (isset($token['oauth_token'], $token['oauth_token_secret'])) {
            $this->token = new OAuth\Consumer($token['oauth_token'], $token['oauth_token_secret']);
        }

        return $token;
    }

    /**
     * Return the information about the last call
     *
     * @return array
     */
    public function getLastRequestInformation()
    {
        return array(
            'http_url' => $this->http_url,
            'http_code' => $this->http_code,
            'http_info' => $this->http_info,
        );
    }
}
