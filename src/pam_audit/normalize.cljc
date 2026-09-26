(ns pam-audit.normalize
  "Portable normalization from camelCase wire maps (or local kebab-case
  maps) into the canonical estate shape consumed by the rule engine.")

(defn normalize-user [u]
  {:id (:userName u (:id u))
   :kind (keyword (or (:kind u) "human"))
   :active (if (contains? u :active) (boolean (:active u)) true)
   :owner-id (:ownerId u (:owner-id u))
   :mfa-enrolled (boolean (:mfaEnrolled u (:mfa-enrolled u)))
   :assurance (keyword (or (:assurance u) "none"))
   :vault-managed (boolean (:vaultManaged u (:vault-managed u)))
   :device-compliant (boolean (:deviceCompliant u (:device-compliant u)))
   :last-login (:lastLogin u (:last-login u))})

(defn normalize-group [g]
  {:id (:id g)
   :privileged (boolean (:privileged g))
   :members (vec (:members g))})

(defn normalize-token [t]
  {:id (:id t)
   :owner-id (:ownerId t (:owner-id t))
   :created (:created t)
   :revoked (boolean (:revoked t))})

(defn normalize-policy
  "Accept both wire (camelCase) and local (kebab-case) shapes."
  [p]
  {:require-mfa (boolean (:requireMfa p (:require-mfa p)))
   :min-assurance (keyword (or (:minAssurance p (:min-assurance p)) "none"))
   :require-adaptive-mfa (boolean (:requireAdaptiveMfa p (:require-adaptive-mfa p)))
   :require-device-posture (boolean (:requireDevicePosture p (:require-device-posture p)))
   :max-inactive-days (or (:maxInactiveDays p (:max-inactive-days p)) 90)
   :privileged-token-ttl-days (or (:privilegedTokenTtlDays p (:privileged-token-ttl-days p)) 180)
   :require-vaulting (boolean (:requireVaulting p (:require-vaulting p)))})
