<?php
/**
 * SocialConnect project
 * @author Ivan Pralnikov <specinweb@gmail.com>
 */
declare(strict_types = 1);

namespace SocialConnect\OpenIDConnect\Provider;

use Psr\Http\Message\RequestInterface;
use SocialConnect\Common\ArrayHydrator;
use SocialConnect\Common\Exception\InvalidArgumentException;
use SocialConnect\JWX\DecodeOptions;
use SocialConnect\JWX\JWT;
use SocialConnect\OAuth2\Exception\InvalidState;
use SocialConnect\OAuth2\Exception\Unauthorized;
use SocialConnect\OAuth2\Exception\UnknownAuthorization;
use SocialConnect\OAuth2\Exception\UnknownState;
use SocialConnect\OpenIDConnect\AccessToken;
use SocialConnect\Provider\AccessTokenInterface;
use SocialConnect\OpenIDConnect\AbstractProvider;
use SocialConnect\Common\Entity\User;
use SocialConnect\Provider\Exception\InvalidAccessToken;

class Talent extends AbstractProvider
{
    const NAME = 'talent';

    /**
     * {@inheritdoc}
     */
    public function getOpenIdUrl()
    {
        return 'https://talent.kruzhok.org/api/oauth/.well-known/openid-configuration';
    }

    /**
     * {@inheritdoc}
     */
    public function getBaseUri()
    {
        return 'https://talent.kruzhok.org/';
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizeUri()
    {
        return 'https://talent.kruzhok.org/oauth/authorize';
    }

    /**
     * {@inheritdoc}
     */
    public function getRequestTokenUri()
    {
        return 'https://talent.kruzhok.org/api/oauth/issue-token/';
    }

    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return self::NAME;
    }

    /**
     * {@inheritdoc}
     */
    public function extractIdentity(AccessTokenInterface $accessToken)
    {
        if (!$accessToken instanceof AccessToken) {
            throw new InvalidArgumentException(
                '$accessToken must be instance AccessToken'
            );
        }

        $jwt = $accessToken->getJwt();

        $hydrator = new ArrayHydrator([
            'sub' => 'id',
            'email' => 'email',
            'email_verified' => 'emailVerified',
            'name' => 'fullname',
            'picture' => 'pictureURL',
            'given_name' => 'firstname',
            'family_name' => 'lastname',
        ]);

        /** @var User $user */
        $user = $hydrator->hydrate(new User(), $jwt->getPayload());

        return $user;
    }

    /**
     * {@inheritdoc}
     */
    public function parseToken(string $body)
    {
        if (empty($body)) {
            throw new InvalidAccessToken('Provider response with empty body');
        }

        $result = json_decode($body, true);
        if ($result) {
            $token = new AccessToken($result);

            return $token;
        }

        throw new InvalidAccessToken('Provider response with not valid JSON');
    }

    /**
     * {@inheritdoc}
     */
    public function getIdentity(AccessTokenInterface $accessToken)
    {
        $response = $this->request('GET', 'api/users/me', [], $accessToken, null, ['Authorization' => 'Bearer ' . $accessToken->getToken()]);

        $hydrator = new ArrayHydrator([
            'id' => 'id',
            'first_name' => 'firstname',
            'middle_name' => 'middlename',
            'last_name' => 'lastname',
            'email' => 'email',
            'emailVerified' => 'is_valid',
            'phone' => 'phone',
            'birthday' => static function ($value, User $user) {
                if (strtotime($value)) {
                    $user->setBirthday(
                        new \DateTime($value)
                    );
                }
            },
            'address' => 'address',
            'avatar' => 'pictureURL',
            'sex' => static function ($value, User $user) {
                if (in_array($value, ['m', 'w'])) {
                    switch ($value) {
                        case 'm':
                            $value = User::SEX_MALE;
                            break;
                        case 'w':
                            $value = User::SEX_FEMALE;
                            break;
                    }
                    $user->setSex($value);
                }
            },
        ]);

        return $hydrator->hydrate(new User(), $response);
    }

    /**
     * {@inheritdoc}
     */
    public function getScopeInline()
    {
        return implode(' ', $this->scope);
    }

    /**
     * {@inheritdoc}
     */
    public function makeAuthUrl(): string
    {
        $urlParameters = $this->getAuthUrlParameters();
        if (!$this->getBoolOption('stateless', false)) {
            $urlParameters['state'] = $this->generateState();
            $this->session->set(
                $this->getStateKey(),
                $urlParameters['state']
            );
        }
        $urlParameters['nonce'] = $this->generateState();
        if (count($this->scope) > 0) {
            $urlParameters['scope'] = $this->getScopeInline();
        }

        return $this->getAuthorizeUri() . '?' . http_build_query($urlParameters);
    }

    public function getAccessTokenByRequestParameters(array $parameters)
    {
        if (isset($parameters['error'])) {
            $message = $parameters['error'] === 'access_denied' ? 'Unauthorized' : $parameters['error'];
            throw new Unauthorized($message);
        }
        if (!isset($parameters['code'])) {
            throw new Unauthorized('Unknown code');
        }
        if (!$this->getBoolOption('stateless', false)) {
            if (!isset($parameters['state'])) {
                throw new UnknownState();
            }
            $this->setStateKey($parameters['state']);
            $state = $this->session->get($this->getStateKey());
            if (!$state) {
                throw new UnknownAuthorization();
            }
            $this->session->delete($this->getStateKey());
            if ($state !== $parameters['state']) {
                throw new InvalidState();
            }
        }

        return $this->getAccessToken($parameters['code']);
    }

    protected function makeAccessTokenRequest(string $code): RequestInterface
    {
        $parameters = [
            'client_id' => $this->consumer->getKey(),
            'client_secret' => $this->consumer->getSecret(),
            'code' => $code,
            'grant_type' => 'authorization_code',
            'redirect_uri' => $this->getRedirectUrl(),
        ];

        return $this->httpStack->createRequest($this->requestHttpMethod, $this->getRequestTokenUri())
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withBody($this->httpStack->createStream(http_build_query($parameters, '', '&')));
    }
}
