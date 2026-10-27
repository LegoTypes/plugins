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
use OPNsense\Base\UserException;
use OPNsense\Core\Config;

/**
 * The settings and the per-member resolvers. A row is checked as the settings form's Save checks the settings: the
 * whole model's validation, so a row a Save would refuse (a gateway that is not a member, a second row for one
 * gateway, a resolver of the other family, a member left with no resolver) is refused and nothing is saved.
 */
class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'unboundupstream';
    protected static $internalModelClass = '\OPNsense\UnboundUpstream\UnboundUpstream';

    /**
     * The per-member resolvers for the page's grid: each row's member and address, both searched.
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
     * Add a per-member resolver from the dialog; nothing is saved when the model refuses it (validate()).
     */
    public function addResolverAction()
    {
        return $this->addBase('resolver', 'resolvers.resolver');
    }

    /**
     * Change a per-member resolver from the dialog; nothing is saved when the model refuses it (validate()).
     */
    public function setResolverAction($uuid)
    {
        return $this->setBase('resolver', 'resolvers.resolver', $uuid);
    }

    /**
     * Delete per-member resolvers by id (one, or several comma-separated). The model is validated without them first,
     * as a Save would be: when it refuses (a member of a group with no Default left with no resolver), nothing is
     * deleted and the refusal is shown, every distinct message on its own line. Core's delBase() is not used, since it
     * saves without validating; its safe-delete check is not needed, as nothing refers to a resolver row.
     */
    public function delResolverAction($uuid)
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        Config::getInstance()->lock();
        $rows = $this->getModel()->resolvers->resolver;
        $result = ['result' => 'not found'];
        foreach (explode(',', (string)$uuid) as $id) {
            if ($id !== '' && $rows->del($id)) {
                $result = ['result' => 'deleted'];
            }
        }
        if ($result['result'] === 'deleted') {
            $refused = [];
            foreach ($this->getModel()->performValidation() as $msg) {
                $refused[] = $msg->getMessage();
            }
            if ($refused !== []) {
                throw new UserException(implode("\n", array_values(array_unique($refused))),
                    gettext('Per-member resolvers'));
            }
            $this->save(false, true);
        }
        return $result;
    }

    /**
     * A row (addBase(), setBase()) is checked against the whole model, as the settings form's Save is, instead of
     * core's default of the row's own messages only: a message on one of the row's fields is reported on that field
     * of the dialog, any other (another row's, the Default's, the group's) on its gateway field, and either refuses
     * the row. The settings form's own check ($node null) is core's.
     *
     * @param \OPNsense\Base\FieldTypes\BaseField|null $node
     * @param string|null $prefix
     * @param bool $validateFullModel
     * @return array{result: string, validations?: array<string, string|list<string>>}
     */
    protected function validate($node = null, $prefix = null, $validateFullModel = false)
    {
        if ($node === null) {
            return parent::validate($node, $prefix, $validateFullModel);
        }
        $result = ['result' => ''];
        foreach ($this->getModel()->performValidation($validateFullModel) as $msg) {
            $own = str_starts_with($msg->getField(), $node->__reference . '.');
            $field = $own ? $prefix . substr($msg->getField(), strlen($node->__reference)) : $prefix . '.gateway';
            $text = $msg->getMessage();
            $result['result'] = 'failed';
            $have = $result['validations'][$field] ?? [];
            $have = is_array($have) ? $have : [$have];
            if (!in_array($text, $have, true)) {
                $have[] = $text;
            }
            $result['validations'][$field] = count($have) === 1 ? $have[0] : $have;
        }
        return $result;
    }
}
