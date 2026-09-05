(ns idira-audit.rules
  "Pure rule engine. Every rule is a pure fn over plain maps:
   users, groups, tokens, policies. No I/O, no clock reads inside
   rules — callers pass `now` (epoch seconds) so results are
   deterministic and trivially testable."
  (:require [clojure.string :as str]))

;; ---------- time helpers (pure) ----------

(def seconds-per-day 86400)

(defn days-between
  "Whole days from epoch-secs `past` to epoch-secs `now`."
  [past now]
  (quot (- now past) seconds-per-day))

;; ---------- group membership ----------

(defn privileged?
  "True when user is a member of any privileged group."
  [user groups]
  (boolean
   (some (fn [g]
           (and (:privileged g)
                (contains? (set (:members g)) (:id user))))
         groups)))

;; ---------- individual rules (each returns nil or a finding map) ----------

(defn orphaned-privileged
  "Privileged account whose owner/sponsor is missing or not itself
   an active human. Mirrors the CSA sponsor-binding gap: a privileged
   NHI or admin with nobody accountable for it."
  [user users-by-id now]
  (let [owner (get users-by-id (:owner-id user))]
    (when (and (:is-privileged user)
               (or (nil? owner)
                   (not= :human (keyword (:kind owner)))
                   (false? (:active owner))))
      {:rule :orphaned-privileged
       :severity :high
       :user (:id user)
       :evidence {:owner-id (:owner-id user)
                  :owner-state (cond (nil? owner) :missing
                                     (not= "human" (:kind owner)) :not-human
                                     :else :inactive)
                  :checked-at now}
       :message (str "privileged account '" (:id user)
                     "' has no active human owner")})))

(defn inactive-privileged
  "Privileged account dormant beyond the inactivity threshold."
  [user now max-inactive-days]
  (when (and (:is-privileged user)
             (:active user)
             (:last-login user)
             (> (days-between (:last-login user) now) max-inactive-days))
    {:rule :inactive-privileged
     :severity :medium
     :user (:id user)
     :evidence {:last-login (:last-login user)
                :dormant-days (days-between (:last-login user) now)
                :threshold-days max-inactive-days}
     :message (str "privileged account '" (:id user) "' dormant beyond "
                   max-inactive-days " days")}))

(defn unvaulted-privileged
  "Privileged account not under vault management (password/session
   not brokered by the PAM vault)."
  [user]
  (when (and (:is-privileged user)
             (not (:vault-managed user)))
    {:rule :unvaulted-privileged
     :severity :high
     :user (:id user)
     :evidence {:vault-managed false}
     :message (str "privileged account '" (:id user)
                   "' is not vault-managed")}))

(defn missing-mfa
  "Active account without MFA enrollment while policy requires it."
  [user policy]
  (when (and (:active user)
             (:require-mfa policy)
             (not (:mfa-enrolled user)))
    {:rule :missing-mfa
     :severity (if (:is-privileged user) :high :medium)
     :user (:id user)
     :evidence {:mfa-enrolled false
                :assurance (:assurance user)}
     :message (str "active account '" (:id user) "' has no MFA enrolled")}))

(defn stale-token
  "API/token credential older than its allowed TTL."
  [token now max-age-days]
  (when (and (not (:revoked token))
             (> (days-between (:created token) now) max-age-days))
    {:rule :stale-token
     :severity :medium
     :subject (:owner-id token)
     :evidence {:token-id (:id token)
                :age-days (days-between (:created token) now)
                :ttl-days max-age-days}
     :message (str "token '" (:id token) "' (owner '" (:owner-id token)
                   "') exceeds max age of " max-age-days " days")}))

;; ---------- entry point ----------

(defn audit-users
  "Run every rule over the estate. Returns a vector of finding maps.
   `estate` = {:users [...] :groups [...] :tokens [...] :policies {...}}
   `now`    = epoch seconds (caller-supplied for determinism)."
  [{:keys [users groups tokens policies]} now]
  (let [users-by-id (into {} (map (juxt :id identity) users))
        max-inactive (or (:max-inactive-days policies) 90)
        token-ttl (or (:privileged-token-ttl-days policies) 180)
        with-priv (map #(assoc % :is-privileged (privileged? % groups)) users)]
    (vec
     (concat
      (keep #(orphaned-privileged % users-by-id now) with-priv)
      (keep #(inactive-privileged % now max-inactive) with-priv)
      (keep unvaulted-privileged with-priv)
      (keep #(missing-mfa % policies) with-priv)
      (keep #(stale-token % now token-ttl) tokens)))))

(defn summarize
  "Severity counts + totals for a findings vector."
  [findings]
  {:total (count findings)
   :by-rule (into (sorted-map) (map (juxt key (comp count val)))
                  (group-by :rule findings))
   :by-severity (into (sorted-map) (map (juxt key (comp count val)))
                      (group-by :severity findings))})
