(ns pam-audit.policy
  "Policy evaluation: does each account meet the MFA / device-posture
   policy? Pure fns — same determinism contract as pam-audit.rules.")

(def assurance-rank
  "Ordered assurance levels; higher index = stronger."
  [:none :password :mfa :adaptive-mfa :phishing-resistant])

(defn- rank [a]
  (or (first (keep-indexed (fn [index level]
                             (when (= level (keyword a)) index))
                           assurance-rank))
      0))

(defn meets-assurance?
  "True when the user's assurance level meets the policy minimum."
  [user min-assurance]
  (>= (rank (:assurance user)) (rank min-assurance)))

(defn evaluate-user
  "Evaluate one user against the MFA/device policy. Returns a map with
   :compliant? plus a vector of :gaps (each {:gap <kw> :detail <str>})."
  [user policy]
  (let [gaps (cond-> []
               (and (:require-mfa policy) (not (:mfa-enrolled user)))
               (conj {:gap :mfa-not-enrolled
                      :detail "MFA required by policy but not enrolled"})

               (and (:mfa-enrolled user)
                    (:min-assurance policy)
                    (not (meets-assurance? user (:min-assurance policy))))
               (conj {:gap :assurance-below-minimum
                      :detail (str "assurance " (:assurance user)
                                   " below minimum " (:min-assurance policy))})

               (and (:require-adaptive-mfa policy)
                    (:is-privileged user)
                    (not= :adaptive-mfa (:assurance user))
                    (not= :phishing-resistant (:assurance user)))
               (conj {:gap :adaptive-mfa-missing
                      :detail "privileged account lacks adaptive MFA assurance"})

               (and (:require-device-posture policy)
                    (not (:device-compliant user)))
               (conj {:gap :device-posture-unknown
                      :detail "no compliant device binding on record"}))]
    {:user (:id user)
     :compliant? (empty? gaps)
     :gaps gaps}))

(defn evaluate-all
  "Evaluate every user; returns {:compliant [...] :non-compliant [...]},
   each entry the per-user map from evaluate-user."
  [users policy privileged-ids]
  (let [results (map #(evaluate-user (assoc % :is-privileged
                                            (contains? privileged-ids (:id %)))
                                     policy)
                     users)]
    {:compliant (filterv :compliant? results)
     :non-compliant (filterv (complement :compliant?) results)}))
