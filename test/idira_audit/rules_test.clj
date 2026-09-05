(ns idira-audit.rules-test
  (:require [clojure.test :refer [deftest is testing]]
            [idira-audit.mock :as mock]
            [idira-audit.rules :as rules]))

(def estate mock/estate-fixture)
(def now mock/now-fixture)

(deftest test-fixture-yields-exactly-five-findings
  (let [findings (rules/audit-users estate now)
        by-rule (group-by :rule findings)]
    (testing "total"
      (is (= 5 (count findings))))
    (testing "one of each expected rule"
      (is (= #{:orphaned-privileged :inactive-privileged
               :unvaulted-privileged :missing-mfa :stale-token}
             (set (keys by-rule))))
      (doseq [[r fs] by-rule]
        (is (= 1 (count fs)) (str "expected exactly 1 " r))))
    (testing "right subjects, right severities"
      (is (= "svc-orphan" (:user (first (:orphaned-privileged by-rule)))))
      (is (= :high (:severity (first (:orphaned-privileged by-rule)))))
      (is (= "svc-dormant" (:user (first (:inactive-privileged by-rule)))))
      (is (= "svc-unvaulted" (:user (first (:unvaulted-privileged by-rule)))))
      (is (= "analyst-nomfa" (:user (first (:missing-mfa by-rule)))))
      (is (= :medium (:severity (first (:missing-mfa by-rule)))))
      (is (= "tok-stale" (get-in (first (:stale-token by-rule))
                                 [:evidence :token-id])))
      (is (= "svc-dormant" (:subject (first (:stale-token by-rule))))))))

(deftest test-clean-accounts-produce-no-findings
  (let [findings (rules/audit-users estate now)
        flagged (set (map #(or (:user %) (:subject %)) findings))]
    (testing "ciso and admin-active are clean"
      (is (not (contains? flagged "ciso")))
      (is (not (contains? flagged "admin-active"))))))

(deftest test-summarize
  (let [s (rules/summarize (rules/audit-users estate now))]
    (is (= 5 (:total s)))
    (is (= {:high 2 :medium 3} (:by-severity s)))))

(deftest test-revoked-tokens-are-ignored
  (let [estate* (update estate :tokens conj
                        {:id "tok-revoked-old" :owner-id "ciso"
                         :created (- now (* 400 86400)) :revoked true})]
    (is (= 5 (count (rules/audit-users estate* now))))))

(deftest test-empty-estate-is-clean
  (is (= [] (rules/audit-users {:users [] :groups [] :tokens []
                                :policies (:policies estate)}
                               now))))
