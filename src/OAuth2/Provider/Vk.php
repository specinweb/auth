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
     * Vk returns email inside AccessToken
     *
     * @var string|null
     */
    protected $email;

    public function getBaseUri()
    {
        return 'https://api.vk.com/';
    }

    public function getAuthorizeUri()
    {
        return 'https://oauth.vk.com/authorize';
    }

    public function getRequestTokenUri()
    {
        return 'https://oauth.vk.com/access_token';
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
        if (!$result || !isset($result['response']) || !is_array($result['response'])) {
            throw new InvalidResponse(
                'API response is not a valid JSON object',
                $response
            );
        }

        return $result;
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
            throw new InvalidResponse(
                'API response not contain access_token field',
                $response
            );
        }

        $this->phone = $response['response']['phone'] ?? null;
        $this->email = $response['response']['email'] ?? null;

        return new AccessToken(['access_token' => $response['response']['access_token']]);
    }

    /**
     * {@inheritdoc}
     */
    public function getIdentity(AccessTokenInterface $accessToken)
    {
        $query = [
            'v' => $this->version,
        ];

        $fields = $this->getArrayOption('identity.fields', []);
        if ($fields) {
            $query['fields'] = implode(',', $fields);
        }
        $response = $this->request('GET', 'method/users.get', $query, $accessToken);

        $hydrator = new ArrayHydrator([
            'id' => 'id',
            'first_name' => 'firstname',
            'last_name' => 'lastname',
            'email' => 'email',
            'has_mobile' => 'hasMobile',
            'bdate' => static function ($value, User $user) {
                if (strtotime($value)) {
                    $user->setBirthday(
                        new \DateTime($value)
                    );
                }
            },
            'sex' => static function ($value, User $user) {
                $user->setSex($value === 1 ? User::SEX_FEMALE : User::SEX_MALE);
            },
            'screen_name' => 'username',
            'nickname' => 'nickname',
            'city' => 'city',
            'country' => 'country',
            'photo_max_orig' => 'pictureURL',
            'photo_200_orig' => 'photoOrig200',
            'photo_400_orig' => 'photoOrig400',
            'personal' => 'personal',
            'photo_max' => 'photoMax',
            'followers_count' => 'followersCount',
            'friend_status' => 'friendStatus',
            'home_town' => 'homeTown',
            'activities' => 'activities',
            'domain' => 'domain',
            'has_photo' => 'hasPhoto',
            'site' => 'site',
            'last_seen' => 'lastSeen',
            'timezone' => 'timezone',
            'universities' => 'universities',
        ]);

        /** @var User $user */
        $user = $hydrator->hydrate(new User(), array_shift($response['response']));

        if (!$user->email) {
            $user->email = $this->email ?: $accessToken->getEmail();
        }

        if ($this->phone) {
            $user->mobilePhone = $this->phone;
        }

        $user->emailVerified = true;

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
