(ns pam-audit.wire
  "Portable conversion from canonical normalized estate data to the
  camelCase wire shape. JSON serialization remains a native concern.")

(defn user->wire [u]
  {:id (:id u) :userName (:id u) :kind (name (:kind u))
   :active (:active u) :ownerId (:owner-id u)
   :mfaEnrolled (:mfa-enrolled u) :assurance (name (:assurance u))
   :vaultManaged (:vault-managed u) :deviceCompliant (:device-compliant u)
   :lastLogin (:last-login u)})

(defn token->wire [t]
  {:id (:id t) :ownerId (:owner-id t)
   :created (:created t) :revoked (:revoked t)})

(defn policy->wire [p]
  {:requireMfa (:require-mfa p) :minAssurance (name (:min-assurance p))
   :requireAdaptiveMfa (:require-adaptive-mfa p)
   :requireDevicePosture (:require-device-posture p)
   :maxInactiveDays (:max-inactive-days p)
   :privilegedTokenTtlDays (:privileged-token-ttl-days p)
   :requireVaulting (:require-vaulting p)})
