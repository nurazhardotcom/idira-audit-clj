(ns pam-audit.cljs-test-runner
  "Node-target runner for the portable ClojureScript parity suite."
  (:require [cljs.test :as test :refer-macros [run-tests]]
            [pam-audit.policy-test]
            [pam-audit.portable-test]
            [pam-audit.rules-test]))

(enable-console-print!)

(defmethod test/report [:cljs.test/default :end-run-tests] [summary]
  (when-not (test/successful? summary)
    (set! (.-exitCode js/process) 1)))

(defn -main [& _]
  (run-tests 'pam-audit.rules-test
             'pam-audit.policy-test
             'pam-audit.portable-test))

(set! *main-cli-fn* -main)
