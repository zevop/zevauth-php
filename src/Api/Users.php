<?php

declare(strict_types=1);

namespace ZevAuth\Api;

use Generator;

/**
 * Your end users. Fields keep the API's camelCase.
 */
final class Users
{
    /** @internal */
    public function __construct(private readonly Transport $transport)
    {
    }

    /**
     * One page of users.
     *
     * @param array<string, string> $metadata public metadata to match, ANDed
     *
     * @return array{data: list<array<string, mixed>>, hasMore: bool, next: string|null, totalCount?: int}
     */
    public function list(?int $limit = null, ?string $after = null, ?string $query = null, array $metadata = []): array
    {
        $params = ['limit' => $limit, 'after' => $after, 'query' => $query];
        foreach ($metadata as $key => $value) {
            $params["metadata[{$key}]"] = $value;
        }

        /** @var array{data: list<array<string, mixed>>, hasMore: bool, next: string|null, totalCount?: int} */
        return $this->transport->request('GET', '/v1/users', $params) ?? ['data' => [], 'hasMore' => false, 'next' => null];
    }

    /**
     * Every user, a page at a time, as you iterate.
     *
     *     foreach ($client->users->iterate(query: 'ada') as $user) { … }
     *
     * @param array<string, string> $metadata
     *
     * @return Generator<int, array<string, mixed>>
     */
    public function iterate(?int $limit = null, ?string $query = null, array $metadata = []): Generator
    {
        $after = null;
        do {
            $page = $this->list($limit, $after, $query, $metadata);
            foreach ($page['data'] as $user) {
                yield $user;
            }
            $after = $page['next'] ?? null;
        } while (($page['hasMore'] ?? false) && $after !== null);
    }

    /** @return array<string, mixed> */
    public function get(string $id): array
    {
        return $this->transport->request('GET', '/v1/users/' . rawurlencode($id)) ?? [];
    }

    /**
     * @param array<string, mixed> $params
     *
     * @return array<string, mixed>
     */
    public function create(array $params): array
    {
        return $this->transport->request('POST', '/v1/users', body: $params) ?? [];
    }

    /**
     * @param array<string, mixed> $params
     *
     * @return array<string, mixed>
     */
    public function update(string $id, array $params): array
    {
        return $this->transport->request('PATCH', '/v1/users/' . rawurlencode($id), body: $params) ?? [];
    }

    /**
     * Blocks or unblocks a user. Blocking ends their sessions.
     *
     * @return array{user: array<string, mixed>, sessionsRevoked: int}
     */
    public function setBlocked(string $id, bool $blocked): array
    {
        /** @var array{user: array<string, mixed>, sessionsRevoked: int} */
        return $this->transport->request('POST', '/v1/users/' . rawurlencode($id) . '/blocked', body: ['blocked' => $blocked]) ?? [];
    }

    /**
     * Signs the user out everywhere.
     *
     * @return array{sessionsRevoked: int}
     */
    public function revokeSessions(string $id): array
    {
        /** @var array{sessionsRevoked: int} */
        return $this->transport->request('POST', '/v1/users/' . rawurlencode($id) . '/sessions/revoke') ?? ['sessionsRevoked' => 0];
    }

    /**
     * Removes the user's two-step verification, for a support case.
     *
     * @return array<string, mixed>|null
     */
    public function resetMfa(string $id, bool $revokeSessions = false): ?array
    {
        return $this->transport->request('DELETE', '/v1/users/' . rawurlencode($id) . '/mfa', ['revokeSessions' => $revokeSessions]);
    }

    public function delete(string $id): void
    {
        $this->transport->request('DELETE', '/v1/users/' . rawurlencode($id));
    }
}
