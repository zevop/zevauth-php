<?php

declare(strict_types=1);

namespace ZevAuth\Laravel;

use Illuminate\Contracts\Auth\Authenticatable;
use ZevAuth\Auth;

/**
 * The signed-in person, as Laravel sees them through the `zevauth` guard.
 *
 * Built from the verified token alone: no database row, no query. Read
 * your own records by `$user->id` (the ZevAuth user id) if you keep any.
 */
final class ZevAuthUser implements Authenticatable
{
    public readonly string $id;
    public readonly ?string $email;
    public readonly ?string $name;
    public readonly ?string $picture;

    public function __construct(public readonly Auth $auth)
    {
        $claims = $auth->claims ?? [];
        $this->id = (string) $auth->userId;
        $this->email = is_string($claims['email'] ?? null) ? $claims['email'] : null;
        $this->name = is_string($claims['name'] ?? null) ? $claims['name'] : null;
        $this->picture = is_string($claims['picture'] ?? null) ? $claims['picture'] : null;
    }

    /** Whether the active organization grants a role and/or permission. */
    public function hasOrg(?string $role = null, ?string $permission = null): bool
    {
        return $this->auth->has($role, $permission);
    }

    public function getAuthIdentifierName(): string
    {
        return 'id';
    }

    public function getAuthIdentifier(): string
    {
        return $this->id;
    }

    public function getAuthPasswordName(): string
    {
        return 'password';
    }

    /** ZevAuth holds passwords; your app never sees one. */
    public function getAuthPassword(): string
    {
        return '';
    }

    public function getRememberToken(): ?string
    {
        return null;
    }

    public function setRememberToken($value): void
    {
    }

    public function getRememberTokenName(): string
    {
        return '';
    }
}
