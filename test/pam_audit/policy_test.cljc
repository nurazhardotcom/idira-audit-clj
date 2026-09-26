(ns pam-audit.policy-test
  (:require #?(:cljs [cljs.test :refer-macros [deftest is]]
               :default [clojure.test :refer [deftest is]])
            [pam-audit.fixture :as fixture]
            [pam-audit.policy :as policy]))

(def users-by-id
  (into {} (map (juxt :id identity) (:users fixture/estate-fixture))))
(def pol (:policies fixture/estate-fixture))
(def priv-ids #{"admin-active" "svc-orphan" "svc-dormant" "svc-unvaulted"})

(deftest test-privileged-without-adaptive-mfa-has-one-gap
  (let [u (assoc (users-by-id "admin-active") :is-privileged true)
        res (policy/evaluate-user u pol)]
    (is (false? (:compliant? res)))
    (is (= [:adaptive-mfa-missing] (mapv :gap (:gaps res))))))

(deftest test-unenrolled-user-has-mfa-and-device-gaps
  (let [u (assoc (users-by-id "analyst-nomfa") :is-privileged false)
        res (policy/evaluate-user u pol)]
    (is (false? (:compliant? res)))
    (is (= #{:mfa-not-enrolled :device-posture-unknown}
           (set (map :gap (:gaps res)))))))

(deftest test-fully-compliant-user
  (let [u (assoc (users-by-id "ciso") :is-privileged false)
        res (policy/evaluate-user u pol)]
    (is (true? (:compliant? res)))
    (is (empty? (:gaps res)))))

(deftest test-evaluate-all-splits-population
  (let [{:keys [compliant non-compliant]}
        (policy/evaluate-all (:users fixture/estate-fixture) pol priv-ids)
        bad-ids (set (map :user non-compliant))]
    (is (= 1 (count compliant)))
    (is (= "ciso" (:user (first compliant))))
    ;; every privileged fixture user lacks adaptive MFA + the unenrolled analyst
    (is (= #{"admin-active" "svc-orphan" "svc-dormant"
             "svc-unvaulted" "analyst-nomfa"}
           bad-ids))))
