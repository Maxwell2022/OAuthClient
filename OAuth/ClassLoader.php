<?php

namespace Maxwell\OAuthClient\OAuth;

/**
 * SPL class loader for OAuthClient classes.
 */
class ClassLoader
{
    const PACKAGE = 'OAuthClient';

    private static $_path;

    /**
     * Registers ClassLoader as an SPL class loader.
     * Inserts self first, retains existing loaders and __autoload()
     *
     * @param string $path Path to OAuthClient classes directory
     */
    public static function register($path)
    {
        self::$_path = $path;
        self::addPath($path);

        if ($loaders = spl_autoload_functions()) {
            array_map('spl_autoload_unregister', $loaders);
        } else {
            $loaders = function_exists('__autoload') ? array('__autoload') : array();
        }
        array_unshift($loaders, array(__CLASS__, 'load'));
        array_map('spl_autoload_register', $loaders);
    }

    /**
     * Attempts to load a Tumblr class file.
     * @see http://php.net/manual/en/function.spl-autoload-register.php
     * @param string $class
     * @return bool
     */
    public static function load($class)
    {
        if (substr($class, 0, strlen(self::PACKAGE)) != self::PACKAGE) {
            return false;
        }

        $path = sprintf(
            '%s/%s.php',
            self::$_path,
            str_replace('\\', '/', $class)
        );

        if (file_exists($path)) {
            require_once($path);
        }
    }

    /**
     * @param mixed $items Path or paths as string or array
     */
    public static function addPath($items)
    {
        $elements = explode(PATH_SEPARATOR, get_include_path());

        set_include_path(implode(
            PATH_SEPARATOR,
            array_unique(array_merge((array)$items, $elements))
        ));
    }
}