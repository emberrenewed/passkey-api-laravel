<?php

namespace App\Enums;

/**
 * Separating challenge flow types is a security measure.
 * A challenge generated for registration MUST NOT be valid for authentication
 * and vice versa. This prevents cross-ceremony replay attacks.
 */
enum WebauthnFlowType: string
{
    case Registration = 'registration';
    case Authentication = 'authentication';
}
