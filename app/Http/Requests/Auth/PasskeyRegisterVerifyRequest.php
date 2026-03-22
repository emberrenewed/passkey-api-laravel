<?php

namespace App\Http\Requests\Auth;

use Illuminate\Foundation\Http\FormRequest;

class PasskeyRegisterVerifyRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            // User identification.
            'user_id' => ['required_without:email', 'nullable', 'integer', 'exists:users,id'],
            'email' => ['required_without:user_id', 'nullable', 'string', 'email', 'exists:users,email'],

            // The attestation response from navigator.credentials.create().
            'id' => ['required', 'string'],
            'rawId' => ['required', 'string'],
            'type' => ['required', 'string', 'in:public-key'],
            'response' => ['required', 'array'],
            'response.clientDataJSON' => ['required', 'string'],
            'response.attestationObject' => ['required', 'string'],
            'response.transports' => ['nullable', 'array'],
            'response.transports.*' => ['string', 'in:internal,hybrid,ble,nfc,usb'],
            'response.publicKey' => ['nullable', 'string'],
            'response.authenticatorData' => ['nullable', 'string'],

            // Optional metadata.
            'authenticatorAttachment' => ['nullable', 'string', 'in:platform,cross-platform'],
            'device_name' => ['nullable', 'string', 'max:255'],
        ];
    }

    public function messages(): array
    {
        return [
            'id.required' => 'Missing credential ID from the authenticator response.',
            'response.clientDataJSON.required' => 'Missing clientDataJSON from the authenticator response.',
            'response.attestationObject.required' => 'Missing attestationObject from the authenticator response.',
        ];
    }
}
