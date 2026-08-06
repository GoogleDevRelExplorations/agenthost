// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ui

import (
	"embed"
	"html/template"
	"log"
	"net/http"
)

//go:embed templates/*.html
var templatesFS embed.FS

var templates = make(map[string]*template.Template)

func init() {
	pages := []string{"status.html", "oauth2.html", "apikey.html", "success.html", "error.html"}
	for _, page := range pages {
		templates[page] = template.Must(template.ParseFS(templatesFS, "templates/layout.html", "templates/"+page))
	}
}

// Render executes the named template wrapped in the base layout.
func Render(w http.ResponseWriter, templateName string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl, ok := templates[templateName]
	if !ok {
		log.Printf("template %s not found", templateName)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if err := tmpl.ExecuteTemplate(w, templateName, data); err != nil {
		log.Printf("failed to execute template %s: %v", templateName, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
