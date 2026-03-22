<?php

namespace App\Exceptions;

use App\Enums\ErrorCode;

class CredentialNotFoundException extends WebAuthnException
{
    public function __construct(string $message = 'The credential was not found.')
    {
        parent::__construct($message, ErrorCode::CREDENTIAL_NOT_FOUND, 404);
    }
}
