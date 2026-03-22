<?php

namespace App\Exceptions;

use App\Enums\ErrorCode;

class DuplicateCredentialException extends WebAuthnException
{
    public function __construct(string $message = 'This credential is already registered.')
    {
        parent::__construct($message, ErrorCode::DUPLICATE_CREDENTIAL, 409);
    }
}
