;;; Copyright (c) 2024 Jens Schmidt
;;;
;;; Licensed under the Apache License, Version 2.0 (the "License");
;;; you may not use this file except in compliance with the License.
;;; You may obtain a copy of the License at
;;; https://www.apache.org/licenses/LICENSE-2.0
;;;
;;; Unless required by applicable law or agreed to in writing, software
;;; distributed under the License is distributed on an "AS IS" BASIS,
;;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;;; See the License for the specific language governing permissions and
;;; limitations under the License.

(;; replace some of the `+' in `c-offset-alist' by literal
 ;; indentation.  That way, these elements are indented with
 ;; blanks, and not with tabs, thus better matching Eclipse's
 ;; alignment model.
 (java-mode . ((indent-tabs-mode . t)
               (tab-width . 2)
               (eval . (smart-tabs-mode 1))
               (eval . (progn
                         (c-set-offset 'inexpr-class 0)
                         (c-set-offset 'statement-cont tab-width)
                         (c-set-offset 'func-decl-cont tab-width)))))
 ;; use a tab width of four for XML files, since Eclipse cannot
 ;; be easily convinced to use a tab width of two for these
 (nxml-mode . ((indent-tabs-mode . t)
               (tab-width . 4))))
