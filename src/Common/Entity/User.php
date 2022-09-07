<?php
/**
 * SocialConnect project
 * @author: Patsura Dmitry @ovr <talk@dmtry.me>
 */

namespace SocialConnect\Common\Entity;

class User extends \stdClass
{
    const SEX_MALE = 'male';
    const SEX_FEMALE = 'female';
    const SEX_OTHER = 'other';

    const SEX_LIST = [
        self::SEX_MALE,
        self::SEX_FEMALE,
        self::SEX_OTHER,
    ];

    /**
     * @var string
     */
    public $id;

    /**
     * @var string
     */
    public $firstname;

    /**
     * @var string
     */
    public $lastname;

    /**
     * @var string
     */
    public $email;

    /**
     * @var bool
     */
    public $emailVerified = false;

    /**
     * @var \DateTime|null
     */
    protected $birthday;

    /**
     * @var string|null
     */
    public $username;

    /**
     * @var string|null
     */
    public $nickname;

    /**
     * @var string|null
     */
    public $city;

    /**
     * @var string|null
     */
    public $country;

    /**
     * Should be female or male
     *
     * @var string|null
     */
    protected $sex;

    /**
     * @var string|null
     */
    public $fullname;

    /**
     * @var string|null
     */
    public $personal;

    /**
     * @var int|null
     */
    public $followersCount;

    /**
     * @var string|null
     */
    public $friendStatus;

    /**
     * @var int|null
     */
    public $hasMobile;

    /**
     * @var int|null
     */
    public $hasPhoto;

    /**
     * @var string|null
     */
    public $homeTown;

    /**
     * @var string|null
     */
    public $domain;

    /**
     * @var string|null
     */
    public $site;

    /**
     * @var float|null
     */
    public $timezone;

    /**
     * @var array
     */
    public $lastSeen = [];

    /**
     * @var string|null
     */
    public $pictureURL;

    /**
     * @var string|null
     */
    public $photoOrig200;

    /**
     * @var string|null
     */
    public $photoOrig400;

    /**
     * @var string|null
     */
    public $photoMax;

    /**
     * @return \DateTime|null
     */
    public function getBirthday(): ?\DateTime
    {
        return $this->birthday;
    }

    /**
     * @param \DateTime|null $birthday
     */
    public function setBirthday(?\DateTime $birthday): void
    {
        $this->birthday = $birthday;
    }

    /**
     * @return string|null
     */
    public function getSex(): ?string
    {
        return $this->sex;
    }

    /**
     * @param string $sex
     */
    public function setSex(string $sex): void
    {
        $this->sex = in_array($sex, self::SEX_LIST) ? $sex : self::SEX_OTHER;
    }
}
