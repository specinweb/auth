<?php
/**
 * SocialConnect project
 * @author: Patsura Dmitry https://github.com/ovr <talk@dmtry.me>
 */
declare(strict_types = 1);

namespace SocialConnect\OAuth2\Provider;

use Psr\Http\Message\ResponseInterface;
use SocialConnect\Common\ArrayHydrator;
use SocialConnect\OAuth2\AccessToken;
use SocialConnect\Provider\AccessTokenInterface;
use SocialConnect\Common\Entity\User;
use SocialConnect\Common\Entity\City;
use SocialConnect\Provider\Exception\InvalidProviderConfiguration;
use SocialConnect\Provider\Exception\InvalidResponse;

class Vk extends \SocialConnect\OAuth2\AbstractProvider
{
    const NAME = 'vk';

    protected $version = '5.199';

    /**
     * {@inheritdoc}
     */
    protected $requestHttpMethod = 'GET';

    protected $phone;

    /**
     * Vk возвращает email внутри AccessToken
     *
     * @var string|null
     */
    protected $email;

    public $responseChangeToken;

    public function getBaseUri()
    {
        return 'https://id.vk.ru/';
    }

    public function getAuthorizeUri()
    {
        return 'https://id.vk.ru/authorize';
    }

    public function getRequestTokenUri()
    {
        return 'https://id.vk.ru/oauth2/auth';
    }

    public function getName()
    {
        return self::NAME;
    }

    /**
     * {@inheritDoc}
     */
    public function prepareRequest(string $method, string $uri, array &$headers, array &$query, AccessTokenInterface $accessToken = null): void
    {
        if ($accessToken) {
            $query['access_token'] = $accessToken->getToken();
        }
    }

    /**
     * @param ResponseInterface $response
     *
     * @return array
     * @throws InvalidResponse
     */
    protected function hydrateResponse(ResponseInterface $response): array
    {
        $result = json_decode($response->getBody()->getContents(), true);
        if (!$result) {
            throw new InvalidResponse(
                'API response is not a valid JSON object',
                $response
            );
        }

        // VK method/userLinking.b2bGet возвращает данные без поля 'response'
        // Для унификации с остальными методами оборачиваем в ['response' => $result]
        if (!isset($result['response']) || !is_array($result['response'])) {
            return ['response' => $result];
        }

        return $result;
    }

    /**
     * Сформировать URL авторизации с использованием PKCE
     * Добавляет параметры code_challenge и code_challenge_method
     *
     * @param string $codeChallenge
     * @param string $method По умолчанию S256
     *
     * @return string
     */
    public function makeAuthUrlWithPkce(string $codeChallenge, string $method = 'S256'): string
    {
        $parameters = $this->getAuthUrlParameters();

        if (!$this->getBoolOption('stateless', false)) {
            $parameters['state'] = $this->generateState();
            $this->session->set(
                $this->getStateKey(),
                $parameters['state']
            );
        }

        if (count($this->scope) > 0) {
            $parameters['scope'] = $this->getScopeInline();
        }

        $parameters['code_challenge'] = $codeChallenge;
        $parameters['code_challenge_method'] = $method;

        return $this->getAuthorizeUri() . '?' . http_build_query($parameters);
    }

    /**
     * Обменять auth_code на Access Token с использованием PKCE (code_verifier)
     *
     * @param string $code
     * @param string $codeVerifier
     * @param bool $useClientSecret По умолчанию true, можно отключить для public клиентов
     *
     * @return AccessToken
     * @throws InvalidResponse
     * @throws \Psr\Http\Client\ClientExceptionInterface
     */
    public function getAccessTokenWithPkce(string $code, string $codeVerifier, ?string $redirectUri = null, ?string $deviceID = null): AccessToken
    {
        $parameters = [
            'client_id' => $this->consumer->getKey(),
            'code' => $code,
            'grant_type' => 'authorization_code',
            'redirect_uri' => $redirectUri ?? $this->getRedirectUrl(),
            'code_verifier' => $codeVerifier,
            'device_id' => $deviceID,
        ];

        $request = $this->httpStack->createRequest('POST', $this->getRequestTokenUri())
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withBody($this->httpStack->createStream(http_build_query($parameters, '', '&')));

        $response = $this->executeRequest($request);

        return $this->parseToken($response->getBody()->getContents());
    }

    /**
     * Обновить Access Token через Refresh Token
     *
     * @param string $refreshToken
     * @param bool $useClientSecret По умолчанию true
     *
     * @return AccessToken
     * @throws InvalidResponse
     * @throws \Psr\Http\Client\ClientExceptionInterface
     */
    public function refreshAccessToken(string $refreshToken, bool $useClientSecret = true): AccessToken
    {
        $parameters = [
            'client_id' => $this->consumer->getKey(),
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
        ];

        if ($useClientSecret) {
            $parameters['client_secret'] = $this->consumer->getSecret();
        }

        $request = $this->httpStack->createRequest('POST', $this->getRequestTokenUri())
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withBody($this->httpStack->createStream(http_build_query($parameters, '', '&')));

        $response = $this->executeRequest($request);

        return $this->parseToken($response->getBody()->getContents());
    }

    /**
     * Запрос userLinking.b2bGet для миграции с внешних OAuth (OK/Mail) на VK ID
     * Требует сервисный токен в заголовке Authorization: Bearer <SERVICE_TOKEN>
     *
     * @param string $serviceToken
     * @param string $userAccessToken
     * @param string $apiVersion По умолчанию 5.243
     *
     * @return array
     * @throws InvalidResponse
     * @throws \Psr\Http\Client\ClientExceptionInterface
     */
    public function getUserLinkingB2B(string $serviceToken, string $userAccessToken, string $apiVersion = '5.243'): array
    {
        $headers = [
            'Authorization' => 'Bearer ' . $serviceToken,
            'Content-Type' => 'application/x-www-form-urlencoded; charset=utf-8',
            'accept' => '*/*',
        ];

        $payload = [
            'v' => $apiVersion,
            'user_access_token' => $userAccessToken,
        ];

        $response = $this->request(
            'POST',
            'method/userLinking.b2bGet',
            [],
            null,
            $payload,
            $headers
        );

        // Сохраним как и в exchangeSilentAuthToken
        $this->responseChangeToken = $response;

        return $response;
    }

    public function exchangeSilentAuthToken(array $payload)
    {
        if (!isset($payload['silent_token'])) {
            throw new InvalidProviderConfiguration(
                "Parameter 'silent_token' doesn`t exists for get access token"
            );
        }
        if (!isset($payload['uuid'])) {
            throw new InvalidProviderConfiguration(
                "Parameter 'uuid' doesn`t exists for get access token"
            );
        }
        if (!isset($payload['service_key'])) {
            throw new InvalidProviderConfiguration(
                "Parameter 'service_key' doesn`t exists for get service token"
            );
        }
        $query = [
            'v' => $this->version,
            'token' => $payload['silent_token'],
            'uuid' => $payload['uuid'],
            'access_token' => $payload['service_key'],
        ];
        $response = $this->request('POST', 'method/auth.exchangeSilentAuthToken', $query);
        if (!isset($response['response']['access_token'])) {
            throw new InvalidResponse('API response not contain access_token field');
        }

        $this->responseChangeToken = $response;

        $this->phone = $response['response']['phone'] ?? null;
        $this->email = $response['response']['email'] ?? null;

        return new AccessToken(['access_token' => $response['response']['access_token']]);
    }

    /**
     * {@inheritdoc}
     */
    public function getIdentity(AccessTokenInterface $accessToken)
    {
        $headers = [
            'Content-Type' => 'application/x-www-form-urlencoded',
        ];

        $payload = [
            'client_id' => $this->consumer->getKey(),
            'access_token' => $accessToken->getToken(),
        ];

        $response = $this->request(
            'POST',
            'oauth2/user_info',
            [],
            null,
            $payload,
            $headers
        );

        $data = isset($response['response']) ? $response['response'] : $response;
        $userData = $data['user'] ?? null;

        if (!is_array($userData)) {
            throw new InvalidResponse('API response does not contain user object');
        }

        $hydrator = new ArrayHydrator([
            'user_id' => 'id',
            'first_name' => 'firstname',
            'last_name' => 'lastname',
            'email' => 'email',
            'avatar' => 'pictureURL',
            'birthday' => static function ($value, User $user) {
                if ($value && strtotime($value)) {
                    $user->setBirthday(new \DateTime($value));
                }
            },
            'sex' => static function ($value, User $user) {
                // 1 — женский, 2 — мужской, 0 — не указан
                if ($value === 1) {
                    $user->setSex(User::SEX_FEMALE);
                } elseif ($value === 2) {
                    $user->setSex(User::SEX_MALE);
                } else {
                    $user->setSex(User::SEX_OTHER);
                }
            },
            'verified' => static function ($value, User $user) {
                $user->setTrusted((bool)$value);
            },
        ]);

        /** @var User $user */
        $user = $hydrator->hydrate(new User(), $userData);

        if (!$user->email) {
            $user->email = $this->email ?: $accessToken->getEmail();
        }

        if ($this->phone) {
            $user->mobilePhone = $this->phone;
        }

        $user->emailVerified = (bool)$user->email;

        return $user;
    }

    public function getCities(AccessTokenInterface $accessToken, int $countryId, string $q): array
    {
        $cities = null;
        $query = [
            'v' => $this->version,
            'country_id' => $countryId,
            'q' => $q,
        ];
        $cityInfo = $this->request('GET', 'method/database.getCities', $query, $accessToken);
        if (isset($cityInfo['response']) && is_array($cityInfo['response'])) {
            foreach (array_pop($cityInfo['response']) as $item) {
                $hydrator = new ArrayHydrator([
                    'id' => 'id',
                    'title' => 'title',
                    'region' => 'region',
                ]);
                /** @var City $city */
                $cities[] = $hydrator->hydrate(new City(), $item);
            }
        }

        return $cities ? array_combine(array_column($cities, 'id'), $cities) : [];
    }
}
