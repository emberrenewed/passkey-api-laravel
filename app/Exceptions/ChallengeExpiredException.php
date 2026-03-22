<?php

namespace App\Exceptions;

use App\Enums\ErrorCode;

class ChallengeExpiredException extends WebAuthnException
{
    public function __construct(string $message = 'The challenge has expired. Please request a new one.')
    {
        parent::__construct($message, ErrorCode::CHALLENGE_EXPIRED, 400);
    }
}
