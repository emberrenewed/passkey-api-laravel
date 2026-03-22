<?php

namespace App\Http\Requests\Auth;

use Illuminate\Foundation\Http\FormRequest;

class PasskeyLoginVerifyRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            // The assertion response from navigator.credentials.get().
            'id' => ['required', 'string'],
            'rawId' => ['required', 'string'],
            'type' => ['required', 'string', 'in:public-key'],
            'response' => ['required', 'array'],
            'response.clientDataJSON' => ['required', 'string'],
            'response.authenticatorData' => ['required', 'string'],
            'response.signature' => ['required', 'string'],
            'response.userHandle' => ['nullable', 'string'],

            // Optional metadata.
            'authenticatorAttachment' => ['nullable', 'string', 'in:platform,cross-platform'],
        ];
    }

    public function messages(): array
    {
        return [
            'id.required' => 'Missing credential ID from the authenticator response.',
            'response.clientDataJSON.required' => 'Missing clientDataJSON from the authenticator response.',
            'response.authenticatorData.required' => 'Missing authenticatorData from the authenticator response.',
            'response.signature.required' => 'Missing signature from the authenticator response.',
        ];
    }
}
