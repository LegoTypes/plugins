<?php

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

namespace OPNsense\UnboundUpstream\Api;

use OPNsense\Base\ApiMutableModelControllerBase;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'unboundupstream';
    protected static $internalModelClass = '\OPNsense\UnboundUpstream\UnboundUpstream';

    /**
     * The per-member resolvers for the page's grid: each row's member and address.
     */
    public function searchResolverAction()
    {
        return $this->searchBase('resolvers.resolver', ['gateway', 'address']);
    }

    /**
     * One per-member resolver, or a new row's fields with no id.
     */
    public function getResolverAction($uuid = null)
    {
        return $this->getBase('resolver', 'resolvers.resolver', $uuid);
    }

    /**
     * Add a per-member resolver from the dialog; nothing is saved when it fails validation.
     */
    public function addResolverAction()
    {
        return $this->addBase('resolver', 'resolvers.resolver');
    }

    /**
     * Change a per-member resolver from the dialog; nothing is saved when it fails validation.
     */
    public function setResolverAction($uuid)
    {
        return $this->setBase('resolver', 'resolvers.resolver', $uuid);
    }

    /**
     * Delete per-member resolvers by id (one, or several comma-separated).
     */
    public function delResolverAction($uuid)
    {
        return $this->delBase('resolvers.resolver', $uuid);
    }
}
