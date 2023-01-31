<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Doctrine\Common\Collections\Collection;
use Doctrine\Common\Collections\ArrayCollection;

use Symfony\Component\Validator\Constraints as Assert;
use Symfony\Bridge\Doctrine\Validator\Constraints\UniqueEntity;

use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\EquatableInterface;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;

use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\Doctrine\UuidGenerator;

/**
 * @ORM\Entity(repositoryClass="App\Repository\UserRepository")
 * @ORM\Table(name="user")
 * @ORM\HasLifecycleCallbacks
 * @UniqueEntity("username")
 * @UniqueEntity("passwordResetCode")
 */
class User implements UserInterface, EquatableInterface, PasswordAuthenticatedUserInterface
{
    /*
    ----------------------------------------------------------------------------
        Local data
    ----------------------------------------------------------------------------
     */

    /**
     * @var string $id
     * @ORM\Column(name="id", type="guid", unique=true, nullable=false)
     * @ORM\Id
     * @ORM\GeneratedValue(strategy="CUSTOM")
     * @ORM\CustomIdGenerator(class=UuidGenerator::class)
     * @Assert\NotBlank(groups={"Intricate"})
     * @Assert\Uuid(strict=true)
     */
    protected $id = Uuid::NIL;

    /**
     * @var string $username
     * @ORM\Column(name="username", type="string", length=200, unique=true, nullable=false)
     * @Assert\NotBlank()
     * @Assert\Type(type="string")
     * @Assert\Length(min=1, max=200)
     */
    protected $username = "";

    /**
     * @var string|null $password
     * @ORM\Column(name="password", type="string", length=128, unique=false, nullable=true)
     * @Assert\Type(type="string")
     * @Assert\Length(min=0, max=128)
     */
    protected $password;

    /**
     * @var string|null $email
     * @ORM\Column(name="email", type="string", length=256, unique=false, nullable=true)
     * @Assert\Type(type="string")
     * @Assert\Length(min=3, max=256)
     * @Assert\Email()
     */
    protected $email;

    /**
     * @var string[] $roles
     * @ORM\Column(name="roles", type="json", unique=false, nullable=false)
     * @Assert\Type(type="array")
     */
    protected $roles = [];



    /*
    ----------------------------------------------------------------------------
        Life cycle functions
    ----------------------------------------------------------------------------
     */

    /**
     * On construct.
     * @return void
     */
    public function onConstruct(): void
    {

    }

    /**
     * To string.
     * @return string
     */
    public function __toString(): string
    {
        if ($s = $this->getUsername()) {
            return $s;
        }

        return $this->getId();
    }

    /**
     * Serialise.
     * @return array<string, mixed> Serialised data
     */
    public function __serialize(): array
    {
        return [
            "id"        => $this->id,
            "username"  => $this->username,
            "password"  => $this->password,
            "email"     => $this->email,
            "roles"     => $this->roles,
        ];
    }

    /**
     * Unserialise.
     * @param  array<string, mixed> $serialized Serialised data
     * @return void
     */
    public function __unserialize(array $serialized): void
    {
        foreach (["id", "username", "password", "email", "roles"] as $property) {
            $value = $serialized[$property];

            switch ($property) {
                case "id":
                case "username":
                    if (!is_string($value)) {
                        break;
                    }
                    $this->$property = $value;
                    break;

                case "password":
                case "email":
                    if (null !== $value && !is_string($value)) {
                        break;
                    }
                    $this->$property = $value;
                    break;

                case "roles":
                    if (!is_array($value)) {
                        break;
                    }
                    $this->$property = $value;
                    break;
            }
        }
    }



    /*
    ----------------------------------------------------------------------------
        Helper functions
    ----------------------------------------------------------------------------
     */

    /**
     * Check if this user has a role.
     * @param  string $role Role
     * @return bool
     */
    public function hasRole(string $role): bool
    {
        if (!($role = trim($role))) {
            throw new \UnexpectedValueException("Role not specified.");
        }

        return \in_array($role, $this->getRoles());
    }



    /*
    ----------------------------------------------------------------------------
        UserInterface functions
    ----------------------------------------------------------------------------
     */

    /** {@inheritdoc} */
    public function getRoles(): array
    {
        if (!\is_array($this->roles)) {
            $this->roles = [];
        }

        sort($this->roles);
        return $this->roles;
    }

    /** {@inheritdoc} */
    public function eraseCredentials(): void
    {
        $this->password = null;
    }

    /** {@inheritdoc} */
    public function getUserIdentifier(): string
    {
        return $this->getUsername();
    }



    /*
    ----------------------------------------------------------------------------
        EquatableInterface functions
    ----------------------------------------------------------------------------
     */

    /**
     * Check if two instances are equal.
     * @param  UserInterface $user Other user object
     * @return bool
     */
    public function isEqualTo(UserInterface $user): bool
    {
        if (!($user instanceof self)) {
            return false;
        }

        foreach (["username", "roles"] as $property) {
            $getProperty = "get" . ucfirst($property);

            if (!method_exists($user, $getProperty) || !method_exists($this, $getProperty)) {
                return false;
            }

            if ($user->$getProperty() !== $this->$getProperty()) {
                return false;
            }
        }

        return true;
    }



    /*
    ----------------------------------------------------------------------------
        Data functions
    ----------------------------------------------------------------------------
     */

    /**
     * Get id
     *
     * @return string
     */
    public function getId(): string
    {
        return $this->id;
    }

     /**
      * Get username
      *
      * @return string
      */
    public function getUsername(): string
    {
        return $this->username;
    }

    /**
     * Set username
     *
     * @param string $username
     *
     * @return self
     */
    public function setUsername(string $username): self
    {
        $this->username = $username;

        return $this;
    }

    /**
     * Get password
     *
     * @return string|null
     */
    public function getPassword(): ?string
    {
        return $this->password;
    }

    /**
     * Set password
     *
     * @param string|null $password
     *
     * @return self
     */
    public function setPassword(?string $password = null): self
    {
        $this->password = $password;

        return $this;
    }

    /**
     * Get email
     *
     * @return string|null
     */
    public function getEmail(): ?string
    {
        return $this->email;
    }

    /**
     * Set email
     *
     * @param string|null $email
     *
     * @return self
     */
    public function setEmail(?string $email = null): self
    {
        $this->email = $email;

        return $this;
    }

    /**
     * Set roles
     *
     * @param string[] $roles
     *
     * @return self
     */
    public function setRoles(array $roles): self
    {
        $this->roles = $roles;

        return $this;
    }
}
