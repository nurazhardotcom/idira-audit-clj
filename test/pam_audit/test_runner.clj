(ns pam-audit.test-runner
  "JVM runner for the portable Clojure/ClojureScript parity suite."
  (:require [clojure.test :as test]
            [pam-audit.policy-test]
            [pam-audit.portable-test]
            [pam-audit.rules-test]))

(defn -main [& _]
  (let [{:keys [fail error]}
        (test/run-tests 'pam-audit.rules-test
                        'pam-audit.policy-test
                        'pam-audit.portable-test)]
    (System/exit (if (zero? (+ fail error)) 0 1))))
