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
     * @var string|null
     */
    public $region;
}
