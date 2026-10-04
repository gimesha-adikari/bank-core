package com.bankingsystem.core.features.auth.domain.repository;

import com.bankingsystem.core.features.auth.domain.Session;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface SessionRepository extends JpaRepository<Session, UUID> {
    Optional<Session> findByTokenFingerprint(String tokenFingerprint);

    @Modifying
    @Transactional
    @Query("DELETE FROM Session s WHERE s.user.userId = :userId")
    void deleteByUserUserId(@Param("userId") UUID userId);
}
