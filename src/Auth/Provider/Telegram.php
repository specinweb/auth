<?php
declare(strict_types=1);

/**
 * SocialConnect project
 * Авторизация в телеграм с помощью виджета javascript
 * Обрабатывает данные возвращаемые ботом в RedirectUrl
 */

namespace SocialConnect\Auth\Provider;

use Exception;
use SocialConnect\Auth\AbstractProvider;
use SocialConnect\Common\ArrayHydrator;
use SocialConnect\OAuth2\Exception\Unauthorized;
use SocialConnect\Common\Entity\User;

class Telegram extends AbstractProvider
{
    const NAME = 'telegram';

    private $allowedKeys = [
        'id',
        'first_name',
        'last_name',
        'username',
        'photo_url',
        'auth_date',
    ];

    public function getName(): string
    {
        return self::NAME;
    }

    public function getIdentity(array $data): object
    {
        $data = $this->checkAuth($data);

        $hydrator = new ArrayHydrator([
            'id' => 'id',
            'first_name' => 'firstname',
            'last_name' => 'lastname',
            'username' => 'username',
            'photo_url' => 'photourl',
        ]);

        return $hydrator->hydrate(new User(), $data);
    }

    /**
     * @throws Exception
     */
    public function getState(): string
    {
        return $this->generateState();
    }

    /**
     * Проверка авторизации
     */
    function checkAuth(array $authData): array
    {
        $checkHash = $authData['hash'] ?? '';
        $authData = array_intersect_key($authData, array_flip($this->allowedKeys));
        $dataCheckArr = [];
        foreach ($authData as $key => $value) {
            $dataCheckArr[] = $key . '=' . $value;
        }
        sort($dataCheckArr);
        $dataCheckString = implode("\n", $dataCheckArr);
        $applicationId = $this->consumer->getKey();
        $secretKey = hash('sha256', $applicationId, true);
        $hash = hash_hmac('sha256', $dataCheckString, $secretKey);
        if (strcmp($hash, $checkHash) !== 0) {
            throw new Unauthorized('Data is NOT from Telegram');
        }
        if (!isset($authData['auth_date']) || ((time() - $authData['auth_date']) > 86400)) {
            throw new Unauthorized('Data is outdated');
        }

        return $authData;
    }
}
