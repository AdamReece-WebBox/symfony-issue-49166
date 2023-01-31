<?php

namespace App\Repository;

use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Symfony\Component\Security\Core\User\PasswordUpgraderInterface;

use App\Entity\User;
use Doctrine\Persistence\ManagerRegistry;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;

/**
 * @template-extends ServiceEntityRepository<\App\Entity\User>
 */
class UserRepository extends ServiceEntityRepository implements PasswordUpgraderInterface
{
    /*
    ----------------------------------------------------------------------------
        Life cycle functions
    ----------------------------------------------------------------------------
     */

    /**
     * Constructor.
     * @param ManagerRegistry $registry Doctrine entity manager registry
     */
    public function __construct(ManagerRegistry $registry)
    {
        if (!($entityFqcn = trim(User::class))) {
            throw new \DomainException("Repository entity class not defined.");
        }

        if (!class_exists($entityFqcn)) {
            throw new \DomainException("Repository entity class not found.");
        }

        /** @psalm-var class-string<T> $entityFqcn */
        parent::__construct($registry, $entityFqcn);
    }



    /*
    ----------------------------------------------------------------------------
        PasswordUpgraderInterface functions
    ----------------------------------------------------------------------------
     */

    /** {@inheritDoc} */
    public function upgradePassword(PasswordAuthenticatedUserInterface $user, string $newHashedPassword): void
    {
        if (!($user instanceof User)) {
            throw new \UnexpectedValueException("User invalid.");
        }

        $user->setPassword($newHashedPassword);
        $this->getEntityManager()->flush();
    }



    /*
    ----------------------------------------------------------------------------
        Repository functions
    ----------------------------------------------------------------------------
     */

    /**
     * Load a user by identifier.
     * @param  string    $usernameOrEmail User identifier (username or email address)
     * @return User|null                  User entity
     */
    public function loadUserByIdentifier(string $usernameOrEmail): ?User
    {
        $qb = $this->createQueryBuilder("u")
            ->select("u")
            ->where("u.username = :usernameOrEmail OR u.email = :usernameOrEmail")
            ->setParameter("usernameOrEmail", $usernameOrEmail)
            ->setMaxResults(1)
        ;

        /** @var User|null $result */
        $result = $qb->getQuery()->getOneOrNullResult();
        return ($result && (get_class($result) === User::class || is_subclass_of($result, User::class, false)) ? $result : null);
    }
}
