<?php

namespace App\Http\Requests\Auth;

use Illuminate\Foundation\Http\FormRequest;

class PasskeyRegisterOptionsRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            // The user_id is required to generate registration options for a specific user.
            // For first-time registration (right after account creation), the user_id is provided.
            // For adding additional passkeys while authenticated, the user is resolved from the token.
            'user_id' => ['required_without:email', 'nullable', 'integer', 'exists:users,id'],
            'email' => ['required_without:user_id', 'nullable', 'string', 'email', 'exists:users,email'],
        ];
    }
}
