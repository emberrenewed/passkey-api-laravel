<?php

namespace App\Exceptions;

use App\Enums\ErrorCode;
use Exception;

class WebAuthnException extends Exception
{
    public function __construct(
        string $message,
        protected ErrorCode $errorCode,
        protected int $httpStatusCode = 400,
        protected array $validationErrors = [],
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    public function getErrorCode(): string
    {
        return $this->errorCode->value;
    }

    public function getHttpStatusCode(): int
    {
        return $this->httpStatusCode;
    }

    public function getValidationErrors(): array
    {
        return $this->validationErrors;
    }
}
