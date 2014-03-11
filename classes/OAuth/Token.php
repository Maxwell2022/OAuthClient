<?php

namespace OAuth;

/**
 * Class Token
 */
class Token
{
    public $key;
    public $secret;

    /**
     * @param string $key the token
     * @param string $secret the token secret
     */
    function __construct($key, $secret)
    {
        $this->key = $key;
        $this->secret = $secret;
    }

    /**
     * Generates the basic string serialization of a token that a server
     * would respond to request_token and access_token calls with
     */
    function to_string()
    {
        return "oauth_token=" .
        Util::urlencode_rfc3986($this->key) .
        "&oauth_token_secret=" .
        Util::urlencode_rfc3986($this->secret);
    }

    function __toString()
    {
        return $this->to_string();
    }
}