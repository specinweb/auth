<?php
/**
 * SocialConnect project
 * @author: Patsura Dmitry https://github.com/ovr <talk@dmtry.me>
 * @author Alexander Fedyashov <a@fedyashov.com>
 */
declare(strict_types = 1);

namespace SocialConnect\OpenIDConnect\Provider;

use SocialConnect\Common\ArrayHydrator;
use SocialConnect\Common\Exception\InvalidArgumentException;
use SocialConnect\JWX\DecodeOptions;
use SocialConnect\JWX\JWT;
use SocialConnect\OpenIDConnect\AccessToken;
use SocialConnect\Provider\AccessTokenInterface;
use SocialConnect\OpenIDConnect\AbstractProvider;
use SocialConnect\Common\Entity\User;
use SocialConnect\Provider\Exception\InvalidAccessToken;

class Mos extends AbstractProvider
{
    const NAME = 'mos';

    /**
     * {@inheritdoc}
     */
    public function getOpenIdUrl()
    {
        return 'https://login-tech.mos.ru/.well-known/jwks';
    }

    /**
     * {@inheritdoc}
     */
    public function getBaseUri()
    {
        return 'https://login-tech.mos.ru/';
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizeUri()
    {
        return 'https://login-tech.mos.ru/sps/oauth/ae';
    }

    /**
     * {@inheritdoc}
     */
    public function getRequestTokenUri()
    {
        return 'https://login-tech.mos.ru/sps/oauth/te';
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
    public function parseToken(string $body)
    {
        if (empty($body)) {
            throw new InvalidAccessToken('Provider response with empty body');
        }

        $result = json_decode($body, true);
        if ($result) {
            $token = new AccessToken($result);

            /** @todo Убрать комментарии когда будет работать https://login-tech.mos.ru/.well-known/jwks
             * $token->setJwt(
             * JWT::decode($result['id_token'], $this->getJWKSet(), new DecodeOptions())
             * );
             */

            return $token;
        }

        throw new InvalidAccessToken('Provider response with not valid JSON');
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
    public function getIdentity(AccessTokenInterface $accessToken)
    {
        $response = $this->request('GET', 'sps/oauth/me', [], $accessToken, null, ['Authorization' => 'Bearer ' . $accessToken->getToken()]);

        $hydrator = new ArrayHydrator([
            'guid' => 'id',
            'FirstName' => 'firstname',
            'LastName' => 'lastname',
            'MiddleName' => 'middlename',
            'email' => 'email',
            'phone_number' => 'mobilePhone',
            'contacts' => 'contacts',
            'trusted' => static function ($value, User $user) {
                $user->setTrusted($value);
            },
            'gender' => static function ($value, User $user) {
                $user->setSex($value);
            },
            'birthDate' => static function ($value, User $user) {
                if (strtotime($value)) {
                    $user->setBirthday(
                        new \DateTime($value)
                    );
                }
            },
        ]);

        /** @var User $user */
        $user = $hydrator->hydrate(new User(), $response);

        $user->hasMobile = (bool)$user->mobilePhone;

        return $user;
    }

    /**
     * {@inheritdoc}
     */
    public function getScopeInline()
    {
        return implode(' ', $this->scope);
    }
}
