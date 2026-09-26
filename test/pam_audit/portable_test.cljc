(ns pam-audit.portable-test
  (:require #?(:cljs [cljs.test :refer-macros [deftest is testing]]
               :default [clojure.test :refer [deftest is testing]])
            [pam-audit.fixture :as fixture]
            [pam-audit.idsvc-core :as idsvc-core]
            [pam-audit.normalize :as normalize]
            [pam-audit.policy :as policy]
            [pam-audit.rules :as rules]
            [pam-audit.wire :as wire]))

(def ^:private day 86400)

(def ^:private expected-fixture-findings
  [{:rule :orphaned-privileged
    :severity :high
    :user "svc-orphan"
    :evidence {:owner-id nil
               :owner-state :missing
               :checked-at fixture/now-fixture}
    :message "privileged account 'svc-orphan' has no active human owner"}
   {:rule :inactive-privileged
    :severity :medium
    :user "svc-dormant"
    :evidence {:last-login 1778092800
               :dormant-days 120
               :threshold-days 90}
    :message "privileged account 'svc-dormant' dormant beyond 90 days"}
   {:rule :unvaulted-privileged
    :severity :high
    :user "svc-unvaulted"
    :evidence {:vault-managed false}
    :message "privileged account 'svc-unvaulted' is not vault-managed"}
   {:rule :missing-mfa
    :severity :medium
    :user "analyst-nomfa"
    :evidence {:mfa-enrolled false
               :assurance :none}
    :message "active account 'analyst-nomfa' has no MFA enrolled"}
   {:rule :stale-token
    :severity :medium
    :subject "svc-dormant"
    :evidence {:token-id "tok-stale"
               :age-days 200
               :ttl-days 180}
    :message "token 'tok-stale' (owner 'svc-dormant') exceeds max age of 180 days"}])

(defn- replace-user [estate id f]
  (update estate :users
          (fn [users]
            (mapv #(if (= id (:id %)) (f %) %) users))))

(defn- replace-token [estate id f]
  (update estate :tokens
          (fn [tokens]
            (mapv #(if (= id (:id %)) (f %) %) tokens))))

(deftest test-exact-five-finding-fixture-contract
  (let [findings (rules/audit-users fixture/estate-fixture fixture/now-fixture)]
    (testing "the complete finding vector, including order and messages"
      (is (= expected-fixture-findings findings)))
    (testing "the exact summary"
      (is (= {:total 5
              :by-rule {:inactive-privileged 1
                        :missing-mfa 1
                        :orphaned-privileged 1
                        :stale-token 1
                        :unvaulted-privileged 1}
              :by-severity {:high 2 :medium 3}}
             (rules/summarize findings))))))

(deftest test-all-six-rules-and-vector-order
  (let [estate (-> fixture/estate-fixture
                   (update :users conj
                           {:id "svc-ghost" :kind :service
                            :active true :owner-id "ciso"
                            :mfa-enrolled true :assurance :mfa
                            :vault-managed true :device-compliant true})
                   (update :groups
                           (fn [groups]
                             (mapv (fn [group]
                                     (if (= "vault-admins" (:id group))
                                       (update group :members conj "svc-ghost")
                                       group))
                                   groups))))
        findings (rules/audit-users estate fixture/now-fixture)
        contract (mapv (fn [finding]
                         [(:rule finding)
                          (:severity finding)
                          (or (:user finding) (:subject finding))])
                       findings)]
    (is (= [[:orphaned-privileged :high "svc-orphan"]
            [:inactive-privileged :medium "svc-dormant"]
            [:never-logged-in-privileged :high "svc-ghost"]
            [:unvaulted-privileged :high "svc-unvaulted"]
            [:missing-mfa :medium "analyst-nomfa"]
            [:stale-token :medium "svc-dormant"]]
           contract))))

(deftest test-strict-day-and-token-thresholds
  (let [now fixture/now-fixture
        dormant (first (filter #(= "svc-dormant" (:id %))
                               (:users fixture/estate-fixture)))
        at-threshold (assoc dormant :is-privileged true
                              :last-login (- now (* 90 day)))
        over-threshold (assoc dormant :is-privileged true
                                 :last-login (- now (* 91 day)))
        almost-threshold (assoc dormant
                                 :last-login (- now (+ (* 90 day) 86399)))
        token-at-threshold {:id "edge" :owner-id "svc-dormant"
                            :created (- now (* 180 day)) :revoked false}
        token-over-threshold (assoc token-at-threshold
                                    :created (- now (* 181 day)))]
    (testing "whole days truncate toward zero"
      (is (= 90 (rules/days-between (:last-login at-threshold) now)))
      (is (= 90 (rules/days-between (:last-login almost-threshold) now))))
    (testing "inactivity uses strict greater-than"
      (is (nil? (rules/inactive-privileged at-threshold now 90)))
      (is (= 91 (get-in (rules/inactive-privileged over-threshold now 90)
                        [:evidence :dormant-days]))))
    (testing "token age uses strict greater-than"
      (is (nil? (rules/stale-token token-at-threshold now 180)))
      (is (= 181 (get-in (rules/stale-token token-over-threshold now 180)
                          [:evidence :age-days]))))))

(deftest test-owner-kind-and-state-normalization
  (let [user {:id "subject" :is-privileged true :owner-id "owner"}
        cases [["active string human" {:kind "human" :active true} nil]
               ["active keyword human" {:kind :human :active true} nil]
               ["active string service" {:kind "service" :active true} :not-human]
               ["active keyword service" {:kind :service :active true} :not-human]
               ["inactive human" {:kind "human" :active false} :inactive]]]
    (doseq [[label owner expected-state] cases]
      (testing label
        (let [finding (rules/orphaned-privileged user {"owner" owner} fixture/now-fixture)]
          (is (if expected-state
                (= expected-state (get-in finding [:evidence :owner-state]))
                (nil? finding))))))
    (is (= :missing
           (get-in (rules/orphaned-privileged user {} fixture/now-fixture)
                   [:evidence :owner-state])))))

(deftest test-portable-assurance-ranking-and-gap-order
  (testing "the public ordered levels are exact"
    (is (= [:none :password :mfa :adaptive-mfa :phishing-resistant]
           policy/assurance-rank)))
  (testing "known assurance levels meet only their threshold and stronger"
    (let [expected-ranks {:none 0
                          :password 1
                          :mfa 2
                          :adaptive-mfa 3
                          :phishing-resistant 4}]
      (doseq [actual policy/assurance-rank
              minimum policy/assurance-rank]
        (is (= (>= (expected-ranks actual) (expected-ranks minimum))
               (policy/meets-assurance? {:assurance actual} minimum))))))
  (testing "unknown, nil, and string values retain the old rank-zero behavior"
    (is (true? (policy/meets-assurance? {:assurance :unknown} :none)))
    (is (false? (policy/meets-assurance? {:assurance :unknown} :password)))
    (is (true? (policy/meets-assurance? {} :none)))
    (is (false? (policy/meets-assurance? {} :password)))
    (is (true? (policy/meets-assurance? {:assurance "mfa"} "mfa"))))
  (testing "gap ordering is causal and deterministic"
    (let [users (into {} (map (juxt :id identity)
                              (:users fixture/estate-fixture)))
          policies (:policies fixture/estate-fixture)
          privileged-without-mfa
          (assoc (users "analyst-nomfa") :is-privileged true)
          below-assurance
          (assoc (users "admin-active") :is-privileged true
                 :assurance :password :device-compliant false)
          without-mfa (policy/evaluate-user privileged-without-mfa policies)
          below (policy/evaluate-user below-assurance policies)]
      (is (= [:mfa-not-enrolled
              :adaptive-mfa-missing
              :device-posture-unknown]
             (mapv :gap (:gaps without-mfa))))
      (is (= [:assurance-below-minimum
              :adaptive-mfa-missing
              :device-posture-unknown]
             (mapv :gap (:gaps below)))))))

(deftest test-wire-shape-and-normalizer-contract
  (let [normalized-user {:id "u-1" :kind :service :active false
                         :owner-id "owner" :mfa-enrolled false
                         :assurance :none :vault-managed false
                         :device-compliant true :last-login 42}
        wire-user {:id "u-1" :userName "u-1" :kind "service" :active false
                   :ownerId "owner" :mfaEnrolled false :assurance "none"
                   :vaultManaged false :deviceCompliant true :lastLogin 42}
        normalized-token {:id "t-1" :owner-id "owner"
                          :created 42 :revoked true}
        wire-token {:id "t-1" :ownerId "owner"
                    :created 42 :revoked true}
        normalized-policy (:policies fixture/estate-fixture)]
    (is (= wire-user (wire/user->wire normalized-user)))
    (is (= normalized-user (normalize/normalize-user wire-user)))
    (is (= {:id "g-1" :privileged true :members ["u-1" "u-2"]}
           (normalize/normalize-group
            {:id "g-1" :privileged true :members ["u-1" "u-2"]})))
    (is (= wire-token (wire/token->wire normalized-token)))
    (is (= normalized-token (normalize/normalize-token wire-token)))
    (is (= {:requireMfa true :minAssurance "mfa"
            :requireAdaptiveMfa true :requireDevicePosture true
            :maxInactiveDays 90 :privilegedTokenTtlDays 180
            :requireVaulting true}
           (wire/policy->wire normalized-policy)))
    (is (= normalized-policy
           (normalize/normalize-policy
            (wire/policy->wire normalized-policy)))))
  (testing "defaults and explicit false remain distinct"
    (is (= {:id "default" :kind :human :active true :owner-id nil
            :mfa-enrolled false :assurance :none :vault-managed false
            :device-compliant false :last-login nil}
           (normalize/normalize-user {:userName "default"})))
    (is (false? (:active (normalize/normalize-user
                          {:userName "inactive" :active false}))))
    (is (= {:require-mfa false :min-assurance :none
            :require-adaptive-mfa false :require-device-posture false
            :max-inactive-days 90 :privileged-token-ttl-days 180
            :require-vaulting false}
           (normalize/normalize-policy {})))))

(deftest test-idsvc-inventory-translation-and-sponsor-binding
  (let [inventory {:humans [{:name "alice"} {:name "bob"}]
                  :non_human_identities
                  [{:name "worker" :sponsor "alice"}
                   {:name "orphan"}]}
        estate (idsvc-core/->estate inventory)
        expected {:users
                  [{:id "alice" :kind :human :active true :owner-id nil
                    :mfa-enrolled false :assurance :none
                    :vault-managed true :device-compliant false
                    :last-login nil}
                   {:id "bob" :kind :human :active true :owner-id nil
                    :mfa-enrolled false :assurance :none
                    :vault-managed true :device-compliant false
                    :last-login nil}
                   {:id "worker" :kind :service :active true
                    :owner-id "alice" :mfa-enrolled true :assurance :mfa
                    :vault-managed true :device-compliant true
                    :last-login nil}
                   {:id "orphan" :kind :service :active true :owner-id nil
                    :mfa-enrolled true :assurance :mfa
                    :vault-managed true :device-compliant true
                    :last-login nil}]
                  :groups [{:id "vault-admins" :privileged true
                            :members ["worker" "orphan"]}]
                  :tokens []
                  :policies {:require-mfa false
                             :max-inactive-days 90
                             :privileged-token-ttl-days 180}}
        findings (rules/audit-users estate fixture/now-fixture)]
    (is (= expected estate))
    (is (= [[:orphaned-privileged "orphan"]
            [:never-logged-in-privileged "worker"]
            [:never-logged-in-privileged "orphan"]]
           (mapv (fn [finding]
                   [(:rule finding) (or (:user finding) (:subject finding))])
                 findings)))))

(deftest test-group-membership-assignment-is-exact
  (let [users [{:id "member" :kind :human :active true :owner-id "member"
                :mfa-enrolled true :assurance :adaptive-mfa
                :vault-managed false :device-compliant true
                :last-login fixture/now-fixture}
               {:id "outsider" :kind :human :active true
                :owner-id "outsider" :mfa-enrolled true
                :assurance :adaptive-mfa :vault-managed true
                :device-compliant true :last-login fixture/now-fixture}]
        groups [{:id "privileged" :privileged true :members ["member"]}
                {:id "ordinary" :privileged false
                 :members ["member" "outsider"]}]
        findings (rules/audit-users {:users users :groups groups
                                     :tokens [] :policies {}}
                                    fixture/now-fixture)]
    (is (= [[:unvaulted-privileged "member"]]
           (mapv (fn [finding]
                   [(:rule finding) (:user finding)])
                 findings)))))

(deftest test-single-field-repairs-remove-only-their-finding
  (let [base-rules [:orphaned-privileged :inactive-privileged
                    :unvaulted-privileged :missing-mfa :stale-token]
        owner-repaired (-> fixture/estate-fixture
                           (replace-user "svc-orphan" #(assoc % :owner-id "ciso")))
        mfa-repaired (-> fixture/estate-fixture
                         (replace-user "analyst-nomfa"
                                       #(assoc % :mfa-enrolled true)))
        token-repaired
        (-> fixture/estate-fixture
            (replace-token "tok-stale"
                           #(assoc % :created
                                   (- fixture/now-fixture (* 180 day)))))]
    (is (= [:inactive-privileged :unvaulted-privileged :missing-mfa :stale-token]
           (mapv :rule (rules/audit-users owner-repaired fixture/now-fixture))))
    (is (= [:orphaned-privileged :inactive-privileged
            :unvaulted-privileged :stale-token]
           (mapv :rule (rules/audit-users mfa-repaired fixture/now-fixture))))
    (is (= (vec (remove #{:stale-token} base-rules))
           (mapv :rule (rules/audit-users token-repaired fixture/now-fixture))))))

(deftest test-ageless-and-revoked-token-contract
  (let [ageless {:id "tok-nodate" :owner-id "svc-dormant" :revoked false}
        finding (rules/stale-token ageless fixture/now-fixture 180)]
    (is (= {:rule :stale-token
            :severity :medium
            :subject "svc-dormant"
            :evidence {:token-id "tok-nodate"
                       :age-days nil
                       :ttl-days 180}
            :message "token 'tok-nodate' (owner 'svc-dormant') has no creation timestamp; age unverifiable"}
           finding))
    (is (nil? (rules/stale-token (assoc ageless :revoked true)
                                 fixture/now-fixture 180)))))
