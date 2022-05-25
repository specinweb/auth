<?php
declare(strict_types=1);

namespace SocialConnect\Auth;

use SocialConnect\Common\HttpStack;
use SocialConnect\Provider\Consumer;
use SocialConnect\Provider\Exception\InvalidProviderConfiguration;
use SocialConnect\Provider\Session\SessionInterface;

abstract class AbstractProvider
{
    const STATE_KEY = 'auth_state:';

    /**
     * @var Consumer
     */
    protected $consumer;

    /**
     * @var HttpStack
     */
    protected $httpStack;

    /**
     * @var SessionInterface
     */
    protected $session;

    /**
     * @var string
     */
    protected $redirectUri;

    /**
     * @var array
     */
    protected $options = [];

    /**
     * Save stateKey
     *
     * @var string
     */
    protected $stateKey;

    /**
     * @return string
     */
    protected function getStateKey(): string
    {
        return $this->stateKey;
    }

    /**
     * @param string $stateKey
     *
     * @return void
     */
    protected function setStateKey(string $stateKey)
    {
        $this->stateKey = self::STATE_KEY . $stateKey;
    }

    /**
     * @param HttpStack $httpStack
     * @param SessionInterface $session
     * @param array $parameters
     *
     * @throws InvalidProviderConfiguration
     */
    public function __construct(HttpStack $httpStack, SessionInterface $session, array $parameters)
    {
        if (isset($parameters['options'])) {
            $this->options = $parameters['options'];
        }

        if (isset($parameters['redirectUri'])) {
            $this->redirectUri = $parameters['redirectUri'];
        }

        if (isset($parameters['state'])) {
            $this->setStateKey($parameters['state']);
        }

        $this->consumer = $this->createConsumer($parameters);
        $this->httpStack = $httpStack;
        $this->session = $session;
    }

    /**
     * Return Provider's name
     *
     * @return string
     */
    abstract public function getName(): string;

    /**
     * @return string
     */
    abstract public function makeAuthUrl(): string;

    /**
     * @param array $parameters
     * @return Consumer
     */
    protected function createConsumer(array $parameters): Consumer
    {
        return new Consumer(
            $this->getRequiredStringParameter('applicationId', $parameters),
            ''
        );
    }

    /**
     * @param string $key
     * @param bool $default
     *
     * @return bool
     */
    public function getBoolOption($key, $default): bool
    {
        if (array_key_exists($key, $this->options)) {
            return (bool)$this->options[$key];
        }

        return $default;
    }

    /**
     * @param int $bytes Default it's 16 bytes / 128 bit / 16 symbols / 32 symbols in hex
     *
     * @return string
     * @throws \Exception
     */
    protected function generateState(int $bytes = 16): string
    {
        $stateKey = bin2hex(random_bytes($bytes));
        $this->setStateKey($stateKey);

        return $stateKey;
    }

    public function getAuthUrlParameters(): array
    {
        $parameters['client_id'] = $this->consumer->getKey();
        $parameters['redirect_uri'] = $this->getRedirectUrl();

        return $parameters;
    }

    /**
     * @param string $key
     * @param array $parameters
     *
     * @return string
     * @throws InvalidProviderConfiguration
     */
    protected function getRequiredStringParameter(string $key, array $parameters): string
    {
        if (!isset($parameters[$key])) {
            throw new InvalidProviderConfiguration(
                "Parameter '{$key}' doesn`t exists for '{$this->getName()}' provider configuration"
            );
        }

        if (!is_string($parameters[$key])) {
            throw new InvalidProviderConfiguration(
                "Parameter '{$key}' must be string inside '{$this->getName()}' provider configuration"
            );
        }

        return $parameters[$key];
    }
}
