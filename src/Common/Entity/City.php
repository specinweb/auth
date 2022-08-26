<?php

namespace SocialConnect\Common\Entity;

class City extends \stdClass
{
    /**
     * @var integer
     */
    public $id;

    /**
     * @var string
     */
    public $title;

    /**
     * Should be female or male
     *
     * @var string|null
     */
    protected $region;
}
