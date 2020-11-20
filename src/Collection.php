<?php
/**
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is “Incompatible With Secondary Licenses”,
 * as defined by the Mozilla Public License, v. 2.0.
 */

namespace Trello;

/**
 * Collection
 * This is a helper class for calling 'get' on collections (Trello->boards->get())
 * It is not necessary to create objects of this type yourself.
 *
 * @author Matt Zuba <matt.zuba@gmail.com>
 * @author Daniel Lowhorn <dlowhorn@gmail.com>
 * @copyright 2013 Matt Zuba
 * @version 1.0
 * @package php-trello
 */
class Collection
{

    /**
     * Different types of collections (boards, members, etc)
     * @var string
     */
    protected $collection;

    /**
     * Trello object so we can call REST api
     * @var \Trello\Trello
     */
    protected $trello;

    /**
     * Supported collections
     */
    protected $collections = array(
        'actions',
        'boards',
        'cards',
        'checklists',
        'labels',
        'lists',
        'members',
        'notifications',
        'organizations',
        'search',
        'tokens',
        'types',
        'webhooks',
    );

    /**
     * Collection constructor.
     *
     * @param $collection
     * @param $trello
     *
     * @throws \Exception
     */
    public function __construct($collection, $trello)
    {
        if (!in_array($collection, $this->collections)) {
            throw new \Exception("Unsupported collection: {$collection}.");
        }

        $this->collection = $collection;
        $this->trello = $trello;
    }

    /**
     * @param $method
     * @param $arguments
     *
     * @return mixed
     * @throws \Exception
     */
    public function __call($method, $arguments)
    {
        if (empty($arguments)) {
            throw new \Exception('Missing path from method call.');
        }
        $path = array_shift($arguments);
        array_unshift($arguments, "$this->collection/$path");
        return call_user_func_array(array($this->trello, $method), $arguments);
    }

}
