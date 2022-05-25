<?php
declare(strict_types = 1);

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

    public function getName(): string
    {
        return self::NAME;
    }

    public function getAuthorizeUri(): string
    {
        return 'https://telegram.org';
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

        return $this->getAuthorizeUri() . '?' . http_build_query($urlParameters);
    }

    public function getRedirectUrl(): string
    {
        return str_replace('${provider}', $this->getName(), $this->redirectUri);
    }

    /**
     * Проверка авторизации
     */
    function checkAuth(array $authData): array
    {
        $checkHash = $authData['hash'] ?? '';
        unset($authData['hash'], $authData['socialName']);
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
