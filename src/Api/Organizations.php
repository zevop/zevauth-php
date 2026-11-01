<?php

declare(strict_types=1);

namespace ZevAuth\Api;

/**
 * Organizations and their members.
 */
final class Organizations
{
    /** @internal */
    public function __construct(private readonly Transport $transport)
    {
    }

    /**
     * The organizations a user belongs to.
     *
     * @return array<string, mixed>
     */
    public function listForUser(string $userId): array
    {
        return $this->transport->request('GET', '/v1/organizations', ['userId' => $userId]) ?? [];
    }

    /** @return array<string, mixed> */
    public function get(string $id): array
    {
        return $this->transport->request('GET', '/v1/organizations/' . rawurlencode($id)) ?? [];
    }

    /**
     * @param array<string, mixed> $params `name`, `slug`, `createdBy`, …
     *
     * @return array<string, mixed>
     */
    public function create(array $params): array
    {
        return $this->transport->request('POST', '/v1/organizations', body: $params) ?? [];
    }

    /**
     * @param array<string, mixed> $params includes `requireMfa`
     *
     * @return array<string, mixed>
     */
    public function update(string $id, array $params): array
    {
        return $this->transport->request('PATCH', '/v1/organizations/' . rawurlencode($id), body: $params) ?? [];
    }

    public function delete(string $id): void
    {
        $this->transport->request('DELETE', '/v1/organizations/' . rawurlencode($id));
    }

    /** @return array<string, mixed> */
    public function addMember(string $id, string $userId, ?string $role = null): array
    {
        $body = ['userId' => $userId];
        if ($role !== null) {
            $body['role'] = $role;
        }

        return $this->transport->request('POST', '/v1/organizations/' . rawurlencode($id) . '/members', body: $body) ?? [];
    }

    public function removeMember(string $id, string $userId): void
    {
        $this->transport->request('DELETE', '/v1/organizations/' . rawurlencode($id) . '/members/' . rawurlencode($userId));
    }
}
