<?php

declare(strict_types=1);

namespace ZevAuth;

/**
 * Who is making a request.
 *
 * Built by `getAuth()`. Signed out is a normal value of this class, not an
 * error: check `$isSignedIn`.
 */
final class Auth
{
    /**
     * @param array<string, mixed>|null $claims every verified claim, or null when signed out
     * @param list<string> $pendingTasks
     */
    public function __construct(
        public readonly bool $isSignedIn,
        public readonly ?string $userId = null,
        public readonly ?string $sessionId = null,
        public readonly ?string $organizationId = null,
        public readonly ?string $organizationRole = null,
        public readonly ?array $claims = null,
        public readonly array $pendingTasks = [],
        public readonly bool $isMfaVerified = false,
        /**
         * True when the request came with no `Authorization` header and its
         * bridge cookie has lapsed: a page should send the browser through
         * the handshake to refresh it. Only the session bridge sets this.
         */
        public readonly bool $needsHandshake = false,
    ) {
    }

    public static function signedOut(bool $needsHandshake = false): self
    {
        return new self(false, needsHandshake: $needsHandshake);
    }

    /**
     * @param array<string, mixed> $claims verified claims
     */
    public static function fromClaims(array $claims): self
    {
        $amr = self::stringList($claims['amr'] ?? null);

        return new self(
            isSignedIn: true,
            userId: is_string($claims['sub'] ?? null) ? $claims['sub'] : null,
            sessionId: is_string($claims['sid'] ?? null) ? $claims['sid'] : null,
            organizationId: is_string($claims['org_id'] ?? null) ? $claims['org_id'] : null,
            organizationRole: is_string($claims['org_role'] ?? null) ? $claims['org_role'] : null,
            claims: $claims,
            pendingTasks: self::stringList($claims['pending_tasks'] ?? null),
            isMfaVerified: in_array('mfa', $amr, true),
        );
    }

    /**
     * Whether the active organization grants a role and/or permission.
     *
     * False with no active organization, and false when you ask for
     * neither. Otherwise every condition you pass must hold.
     *
     *     $auth->has(permission: 'org:members:manage');
     *     $auth->has(role: 'org:admin');
     */
    public function has(?string $role = null, ?string $permission = null): bool
    {
        if ($this->organizationId === null) {
            return false;
        }
        if ($role === null && $permission === null) {
            return false;
        }
        if ($role !== null && $this->organizationRole !== $role) {
            return false;
        }
        if ($permission !== null) {
            $granted = self::stringList($this->claims['org_permissions'] ?? null);
            if (!in_array($permission, $granted, true)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @return list<string>
     */
    private static function stringList(mixed $value): array
    {
        if (!is_array($value)) {
            return [];
        }

        return array_values(array_filter($value, 'is_string'));
    }
}
