<?php

namespace App\Http\Requests\Auth;

use Illuminate\Foundation\Http\FormRequest;

class PasskeyLoginOptionsRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            // Email is optional: if provided, enables email-first flow with allowCredentials.
            // If omitted, enables discoverable credential (username-less) login.
            'email' => ['nullable', 'string', 'email', 'max:255'],
        ];
    }
}
