<?php
declare(strict_types=1);

/**
 * SocialConnect project
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
    function checkAuth(array $auth_data): array
    {
        $check_hash = $auth_data['hash'] ?? '';
        unset($auth_data['hash']);
        $data_check_arr = [];
        foreach ($auth_data as $key => $value) {
            $data_check_arr[] = $key . '=' . $value;
        }
        sort($data_check_arr);
        $data_check_string = implode("\n", $data_check_arr);
        $secret_key = hash('sha256', getenv('TELEGRAM_BOT_TOKEN'), true);
        $hash = hash_hmac('sha256', $data_check_string, $secret_key);
        if (strcmp($hash, $check_hash) !== 0) {
            throw new Unauthorized('Data is NOT from Telegram');
        }
        if ((time() - $auth_data['auth_date']) > 86400) {
            throw new Unauthorized('Data is outdated');
        }

        return $auth_data;
    }
}
