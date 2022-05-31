<?php
declare(strict_types=1);

namespace SocialConnect\Auth;

use SocialConnect\Common\HttpStack;
use SocialConnect\Provider\Consumer;
use SocialConnect\Provider\Exception\InvalidProviderConfiguration;
use SocialConnect\Provider\Session\SessionInterface;

abstract class AbstractProvider
{
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
    abstract public function getState(): string;

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
