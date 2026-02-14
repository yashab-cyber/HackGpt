#!/usr/bin/env python3
"""
Advanced AI Engine for HackGPT
Context-aware analysis with memory and pattern recognition
"""

import os
import json
import logging
import hashlib
import time
import numpy as np
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import subprocess
import requests

# ML and AI imports
try:
    import openai
    from transformers import pipeline, AutoTokenizer, AutoModel
    import torch
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.cluster import KMeans
    from sklearn.metrics.pairwise import cosine_similarity
except ImportError as e:
    logging.warning(f"Some AI dependencies not available: {e}")

from database import get_db_manager, AIContext

@dataclass
class AnalysisResult:
    """Structured analysis result"""
    summary: str
    risk_assessment: Dict[str, Any]
    recommendations: List[str]
    next_actions: List[str]
    confidence_score: float
    patterns_detected: List[str]
    context_used: Dict[str, Any]

@dataclass 
class VulnerabilityPattern:
    """Vulnerability pattern for ML recognition"""
    pattern_id: str
    pattern_type: str
    indicators: List[str]
    severity_prediction: str
    confidence: float
    remediation_template: str

class PatternRecognizer:
    """Machine learning-based pattern recognition"""
    
    def __init__(self):
        self.patterns = self._load_vulnerability_patterns()
        self.vectorizer = TfidfVectorizer(max_features=5000, stop_words='english')
        self.kmeans = None
        self.pattern_vectors = None
        self._initialize_ml_models()
        
    def _load_vulnerability_patterns(self) -> List[VulnerabilityPattern]:
        """Load known vulnerability patterns"""
        patterns = [
            VulnerabilityPattern(
                pattern_id="sql_injection",
                pattern_type="web_vuln",
                indicators=["error", "mysql", "syntax", "sql", "database", "union", "select"],
                severity_prediction="high",
                confidence=0.9,
                remediation_template="Use parameterized queries and input validation"
            ),
            VulnerabilityPattern(
                pattern_id="xss",
                pattern_type="web_vuln", 
                indicators=["script", "alert", "document", "cookie", "javascript", "payload"],
                severity_prediction="medium",
                confidence=0.85,
                remediation_template="Implement proper output encoding and CSP"
            ),
            VulnerabilityPattern(
                pattern_id="directory_traversal",
                pattern_type="web_vuln",
                indicators=["../", "..\\", "path", "file", "directory", "traversal"],
                severity_prediction="high",
                confidence=0.8,
                remediation_template="Validate and sanitize file path inputs"
            ),
            VulnerabilityPattern(
                pattern_id="weak_authentication",
                pattern_type="auth_vuln",
                indicators=["password", "weak", "default", "admin", "login", "authentication"],
                severity_prediction="high",
                confidence=0.75,
                remediation_template="Implement strong password policies and MFA"
            ),
            VulnerabilityPattern(
                pattern_id="privilege_escalation",
                pattern_type="system_vuln",
                indicators=["root", "sudo", "privilege", "escalation", "setuid", "permissions"],
                severity_prediction="critical",
                confidence=0.9,
                remediation_template="Apply principle of least privilege and patch management"
            ),
        ]
        return patterns
    
    def _initialize_ml_models(self):
        """Initialize ML models for pattern recognition"""
        try:
            # Create pattern corpus for training
            pattern_texts = []
            for pattern in self.patterns:
                pattern_text = " ".join(pattern.indicators)
                pattern_texts.append(pattern_text)
            
            if pattern_texts:
                self.pattern_vectors = self.vectorizer.fit_transform(pattern_texts)
                
                # Train clustering model
                self.kmeans = KMeans(n_clusters=min(len(pattern_texts), 5), random_state=42)
                self.kmeans.fit(self.pattern_vectors)
                
            logging.info("ML models initialized successfully")
            
        except Exception as e:
            logging.error(f"Error initializing ML models: {e}")
    
    def detect_patterns(self, text: str) -> List[Tuple[VulnerabilityPattern, float]]:
        """Detect vulnerability patterns in text"""
        if not self.pattern_vectors:
            return []
            
        try:
            # Vectorize input text
            text_vector = self.vectorizer.transform([text.lower()])
            
            # Calculate similarity with known patterns
            similarities = cosine_similarity(text_vector, self.pattern_vectors)[0]
            
            detected_patterns = []
            for i, similarity in enumerate(similarities):
                if similarity > 0.3:  # Threshold for pattern detection
                    pattern = self.patterns[i]
                    confidence = similarity * pattern.confidence
                    detected_patterns.append((pattern, confidence))
            
            # Sort by confidence
            detected_patterns.sort(key=lambda x: x[1], reverse=True)
            return detected_patterns[:5]  # Return top 5 patterns
            
        except Exception as e:
            logging.error(f"Error in pattern detection: {e}")
            return []
    
    def predict_vulnerability_type(self, indicators: List[str]) -> Dict[str, float]:
        """Predict vulnerability type based on indicators"""
        indicator_text = " ".join(indicators).lower()
        patterns = self.detect_patterns(indicator_text)
        
        predictions = {}
        for pattern, confidence in patterns:
            predictions[pattern.pattern_type] = max(predictions.get(pattern.pattern_type, 0), confidence)
        
        return predictions

class ContextManager:
    """Manages AI context and memory"""
    
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.db = get_db_manager()
        self.context_cache = {}
        self.max_context_age = timedelta(hours=24)
        
    def get_session_context(self) -> Dict[str, Any]:
        """Get accumulated context for session"""
        # Check cache first
        cache_key = f"session_context_{self.session_id}"
        if cache_key in self.context_cache:
            return self.context_cache[cache_key]
        
        # Retrieve from database
        ai_contexts = self.db.get_ai_context(self.session_id)
        
        context = {
            'target_info': {},
            'discovered_services': [],
            'vulnerabilities': [],
            'attack_vectors': [],
            'patterns': [],
            'previous_phases': []
        }
        
        for ai_context in ai_contexts:
            context_data = ai_context.context_data
            context_type = ai_context.context_type
            
            if context_type == 'target':
                context['target_info'].update(context_data)
            elif context_type == 'vulnerability':
                context['vulnerabilities'].append(context_data)
            elif context_type == 'service':
                context['discovered_services'].extend(context_data.get('services', []))
            elif context_type == 'phase':
                context['previous_phases'].append(context_data)
        
        # Cache the result
        self.context_cache[cache_key] = context
        return context
    
    def update_context(self, context_type: str, data: Dict[str, Any], confidence: float = 1.0):
        """Update context with new information"""
        self.db.save_ai_context(self.session_id, context_type, data, confidence)
        
        # Invalidate cache
        cache_key = f"session_context_{self.session_id}"
        if cache_key in self.context_cache:
            del self.context_cache[cache_key]
    
    def get_relevant_context(self, query: str, context_type: str = None) -> Dict[str, Any]:
        """Get context relevant to a specific query"""
        all_context = self.get_session_context()
        
        if context_type:
            return all_context.get(context_type, {})
        
        # Use simple keyword matching for relevance
        relevant_context = {}
        query_words = set(query.lower().split())
        
        for key, value in all_context.items():
            if isinstance(value, (list, dict)):
                value_text = json.dumps(value).lower()
                if any(word in value_text for word in query_words):
                    relevant_context[key] = value
        
        return relevant_context

class VulnerabilityCorrelator:
    """Correlates vulnerabilities to identify attack chains"""
    
    def __init__(self):
        self.db = get_db_manager()
        
    def correlate_findings(self, session_id: str, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Correlate vulnerabilities to find attack chains"""
        attack_chains = self._build_attack_chains(vulnerabilities)
        compound_risks = self._calculate_compound_risk(attack_chains)
        exploitation_priority = self._prioritize_exploits(attack_chains, compound_risks)
        
        # Save attack chains to database
        for i, chain in enumerate(attack_chains):
            self.db.create_attack_chain(
                session_id=session_id,
                vulnerability_id=chain.get('primary_vulnerability_id', ''),
                chain_sequence=i,
                exploit_path=chain['steps'],
                risk_score=compound_risks.get(i, 0.0),
                impact_description=chain.get('impact', '')
            )
        
        return {
            'attack_chains': attack_chains,
            'risk_assessment': compound_risks,
            'exploitation_priority': exploitation_priority
        }
    
    def _build_attack_chains(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build potential attack chains from vulnerabilities"""
        chains = []
        
        # Group vulnerabilities by type and system
        web_vulns = [v for v in vulnerabilities if v.get('category') == 'web']
        system_vulns = [v for v in vulnerabilities if v.get('category') == 'system']
        network_vulns = [v for v in vulnerabilities if v.get('category') == 'network']
        
        # Build web application attack chains
        if web_vulns:
            for vuln in web_vulns:
                if vuln.get('severity') in ['critical', 'high']:
                    chain = {
                        'name': f"Web Application Attack via {vuln['title']}",
                        'primary_vulnerability_id': vuln.get('id', ''),
                        'steps': [
                            {'step': 1, 'action': 'Exploit web vulnerability', 'vuln': vuln['title']},
                            {'step': 2, 'action': 'Gain initial access', 'method': 'web_shell'},
                            {'step': 3, 'action': 'Enumerate system', 'tools': ['linpeas', 'enum4linux']},
                        ],
                        'impact': 'Initial system access and potential lateral movement',
                        'likelihood': 0.8 if vuln.get('severity') == 'critical' else 0.6
                    }
                    
                    # Add privilege escalation if system vulns exist
                    if system_vulns:
                        chain['steps'].append({
                            'step': 4, 'action': 'Privilege escalation', 
                            'vulns': [v['title'] for v in system_vulns[:2]]
                        })
                        chain['impact'] += ', privilege escalation to root'
                        chain['likelihood'] *= 0.9
                    
                    chains.append(chain)
        
        # Build network attack chains
        if network_vulns:
            for vuln in network_vulns:
                if vuln.get('severity') in ['critical', 'high']:
                    chain = {
                        'name': f"Network Attack via {vuln['title']}",
                        'primary_vulnerability_id': vuln.get('id', ''),
                        'steps': [
                            {'step': 1, 'action': 'Network reconnaissance', 'vuln': vuln['title']},
                            {'step': 2, 'action': 'Service exploitation', 'method': 'direct_exploit'},
                            {'step': 3, 'action': 'Lateral movement', 'scope': 'network_segment'},
                        ],
                        'impact': 'Network compromise and lateral movement',
                        'likelihood': 0.7
                    }
                    chains.append(chain)
        
        return chains
    
    def _calculate_compound_risk(self, attack_chains: List[Dict[str, Any]]) -> Dict[int, float]:
        """Calculate compound risk scores for attack chains"""
        risks = {}
        
        for i, chain in enumerate(attack_chains):
            # Base risk from likelihood
            base_risk = chain.get('likelihood', 0.5)
            
            # Multiply by number of steps (more complex = higher risk if successful)
            complexity_multiplier = min(len(chain.get('steps', [])) * 0.2, 2.0)
            
            # Impact factor based on description
            impact_keywords = ['root', 'admin', 'critical', 'network', 'data']
            impact_score = sum(1 for keyword in impact_keywords 
                             if keyword in chain.get('impact', '').lower())
            impact_factor = min(1.0 + (impact_score * 0.3), 3.0)
            
            # Calculate final compound risk (0-10 scale)
            compound_risk = base_risk * complexity_multiplier * impact_factor * 3.33
            risks[i] = min(compound_risk, 10.0)
        
        return risks
    
    def _prioritize_exploits(self, attack_chains: List[Dict[str, Any]], 
                           compound_risks: Dict[int, float]) -> List[Dict[str, Any]]:
        """Prioritize exploits based on risk and feasibility"""
        prioritized = []
        
        for i, chain in enumerate(attack_chains):
            risk_score = compound_risks.get(i, 0.0)
            likelihood = chain.get('likelihood', 0.5)
            
            # Priority score combines risk and likelihood
            priority_score = (risk_score * 0.6) + (likelihood * 10 * 0.4)
            
            prioritized.append({
                'chain_index': i,
                'chain_name': chain['name'],
                'priority_score': priority_score,
                'risk_score': risk_score,
                'likelihood': likelihood,
                'recommendation': self._get_exploit_recommendation(chain, risk_score)
            })
        
        # Sort by priority score (highest first)
        prioritized.sort(key=lambda x: x['priority_score'], reverse=True)
        
        return prioritized
    
    def _get_exploit_recommendation(self, chain: Dict[str, Any], risk_score: float) -> str:
        """Get recommendation for exploit prioritization"""
        if risk_score >= 8.0:
            return "CRITICAL: Exploit immediately - high impact, high likelihood"
        elif risk_score >= 6.0:
            return "HIGH: Priority exploit - significant risk"
        elif risk_score >= 4.0:
            return "MEDIUM: Consider for exploitation after high priority items"
        else:
            return "LOW: Low priority - consider for comprehensive testing"

class AdvancedAIEngine:
    """Advanced AI Engine with context awareness and ML capabilities"""
    
    def __init__(self, session_id: str = None):
        self.session_id = session_id
        self.api_key = os.getenv('OPENAI_API_KEY')
        self.local_mode = not bool(self.api_key)
        
        # Initialize components
        self.pattern_recognizer = PatternRecognizer()
        self.vulnerability_correlator = VulnerabilityCorrelator()
        
        if session_id:
            self.context_manager = ContextManager(session_id)
        
        self.logger = logging.getLogger(__name__)
        
        # Initialize AI models
        self._setup_ai_models()
        
    def _setup_ai_models(self):
        """Setup AI models (OpenAI or local)"""
        if not self.local_mode:
            self.logger.info("Using OpenAI API for AI analysis")
        else:
            self.logger.info("Setting up local AI models...")
            self._setup_local_models()
    
    def _setup_local_models(self):
        """Setup local AI models"""
        try:
            # Try to use a local model or Hugging Face transformers
            self.local_analyzer = pipeline(
                "text-classification", 
                model="distilbert-base-uncased-finetuned-sst-2-english",
                device=-1  # Use CPU
            )
            self.logger.info("Local AI models setup complete")
        except Exception as e:
            self.logger.warning(f"Could not setup local AI models: {e}")
            self.local_analyzer = None
    
    def analyze_with_context(self, data: str, phase: str, context_type: str = "general") -> AnalysisResult:
        """Perform context-aware analysis"""
        try:
            # Get relevant context
            relevant_context = {}
            if self.context_manager:
                relevant_context = self.context_manager.get_relevant_context(data, context_type)
            
            # Detect patterns
            detected_patterns = self.pattern_recognizer.detect_patterns(data)
            pattern_info = [f"{p[0].pattern_type}: {p[0].pattern_id} (confidence: {p[1]:.2f})" 
                          for p in detected_patterns]
            
            # Create enhanced prompt with context
            prompt = self._create_context_aware_prompt(data, phase, relevant_context, detected_patterns)
            
            # Get AI analysis
            if self.local_mode:
                analysis_text = self._analyze_local(prompt)
            else:
                analysis_text = self._analyze_openai(prompt)
            
            # Parse and structure the analysis
            structured_analysis = self._structure_analysis(analysis_text, detected_patterns)
            
            # Update context with new findings
            if self.context_manager:
                self.context_manager.update_context(
                    context_type, 
                    {
                        'phase': phase,
                        'findings': structured_analysis.summary,
                        'patterns': pattern_info,
                        'timestamp': datetime.utcnow().isoformat()
                    },
                    structured_analysis.confidence_score
                )
            
            return structured_analysis
            
        except Exception as e:
            self.logger.error(f"Error in context-aware analysis: {e}")
            # Return basic analysis as fallback
            return AnalysisResult(
                summary=f"Error in analysis: {str(e)}",
                risk_assessment={'error': True},
                recommendations=["Review analysis system"],
                next_actions=["Check logs for details"],
                confidence_score=0.1,
                patterns_detected=[],
                context_used={}
            )
    
    def _create_context_aware_prompt(self, data: str, phase: str, context: Dict[str, Any], 
                                   patterns: List[Tuple]) -> str:
        """Create context-aware prompt"""
        context_summary = ""
        if context:
            context_summary = f"\nPrevious Context:\n{json.dumps(context, indent=2, default=str)[:1000]}..."
        
        pattern_summary = ""
        if patterns:
            pattern_summary = f"\nDetected Patterns:\n"
            for pattern, confidence in patterns[:3]:
                pattern_summary += f"- {pattern.pattern_type}: {pattern.pattern_id} (confidence: {confidence:.2f})\n"
        
        prompt = f"""
You are HackGPT, an expert penetration testing AI assistant with advanced pattern recognition.

Current Phase: {phase}
Data to Analyze: {data}

{context_summary}

{pattern_summary}

Please provide a comprehensive analysis including:
1. **Summary**: Key findings and their significance
2. **Risk Assessment**: Severity levels, CVSS estimates, business impact
3. **Pattern Analysis**: How detected patterns relate to known vulnerability types
4. **Context Integration**: How findings relate to previous phases and discoveries
5. **Recommendations**: Specific actions to take
6. **Next Actions**: Concrete steps for the next phase
7. **Confidence Score**: Your confidence in the analysis (0.0-1.0)

Format your response as clear, actionable insights for penetration testers.
"""
        return prompt
    
    def _analyze_openai(self, prompt: str) -> str:
        """Analyze using OpenAI API"""
        try:
            client = openai.OpenAI(api_key=self.api_key)
            model = os.getenv('OPENAI_MODEL', 'gpt-3.5-turbo')
            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=2000,
                temperature=0.7
            )
            return response.choices[0].message.content
        except Exception as e:
            self.logger.error(f"OpenAI API error: {e}")
            return f"AI Analysis Error: {str(e)}"
    
    def _analyze_local(self, prompt: str) -> str:
        """Analyze using local models"""
        try:
            if self.local_analyzer:
                # This is a simplified local analysis - in production you'd use a more sophisticated model
                sentiment = self.local_analyzer(prompt[:512])[0]
                
                return f"""
                Local AI Analysis:
                Based on pattern recognition and local processing:
                
                Summary: Detected technical content with {sentiment['label']} sentiment (confidence: {sentiment['score']:.2f})
                
                Risk Assessment: Requires manual review for accurate risk assessment
                
                Recommendations:
                - Review findings manually
                - Consider upgrading to cloud AI for better analysis
                - Use pattern matching results for initial assessment
                
                Note: This is a simplified local analysis. For production use, consider OpenAI API or specialized security AI models.
                """
            else:
                return "Local AI analysis not available. Please configure OpenAI API key or install required models."
                
        except Exception as e:
            return f"Local AI Error: {str(e)}"
    
    def _structure_analysis(self, analysis_text: str, patterns: List[Tuple]) -> AnalysisResult:
        """Structure the AI analysis into components"""
        # Simple parsing - in production, you might use more sophisticated NLP
        lines = analysis_text.split('\n')
        
        summary = ""
        risk_assessment = {}
        recommendations = []
        next_actions = []
        confidence_score = 0.7  # Default confidence
        
        current_section = ""
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Detect sections
            if "summary" in line.lower() and (":" in line or "#" in line):
                current_section = "summary"
                continue
            elif "risk" in line.lower() and (":" in line or "#" in line):
                current_section = "risk"
                continue  
            elif "recommendation" in line.lower() and (":" in line or "#" in line):
                current_section = "recommendations"
                continue
            elif "next" in line.lower() and "action" in line.lower() and (":" in line or "#" in line):
                current_section = "actions"
                continue
            elif "confidence" in line.lower() and (":" in line or "#" in line):
                current_section = "confidence"
                continue
            
            # Parse content based on current section
            if current_section == "summary" and line:
                summary += line + " "
            elif current_section == "recommendations" and line.startswith(('-', '•', '*')):
                recommendations.append(line[1:].strip())
            elif current_section == "actions" and line.startswith(('-', '•', '*')):
                next_actions.append(line[1:].strip())
            elif current_section == "confidence":
                # Try to extract confidence score
                import re
                match = re.search(r'(\d+\.?\d*)', line)
                if match:
                    try:
                        confidence_score = min(float(match.group(1)), 1.0)
                        if confidence_score > 1.0:
                            confidence_score = confidence_score / 10.0  # Handle percentages
                    except ValueError:
                        pass
        
        # Extract risk assessment from patterns
        for pattern, pattern_confidence in patterns:
            risk_assessment[pattern.pattern_id] = {
                'severity': pattern.severity_prediction,
                'confidence': pattern_confidence,
                'type': pattern.pattern_type
            }
        
        return AnalysisResult(
            summary=summary.strip() or "Analysis completed",
            risk_assessment=risk_assessment,
            recommendations=recommendations or ["Continue with next phase"],
            next_actions=next_actions or ["Proceed to next testing phase"],
            confidence_score=confidence_score,
            patterns_detected=[f"{p[0].pattern_id}" for p in patterns],
            context_used=self.context_manager.get_session_context() if self.context_manager else {}
        )
    
    def correlate_vulnerabilities(self, session_id: str, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Correlate vulnerabilities to identify attack chains"""
        return self.vulnerability_correlator.correlate_findings(session_id, vulnerabilities)
    
    def generate_custom_payloads(self, vulnerability_info: Dict[str, Any], target_info: Dict[str, Any]) -> List[str]:
        """Generate custom payloads for specific vulnerabilities"""
        payloads = []
        
        vuln_type = vulnerability_info.get('type', '').lower()
        
        if 'sql' in vuln_type:
            payloads.extend([
                "' OR '1'='1",
                "' UNION SELECT user(), database(), version() --",
                "'; DROP TABLE users; --"
            ])
        elif 'xss' in vuln_type:
            payloads.extend([
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')"
            ])
        elif 'command' in vuln_type or 'injection' in vuln_type:
            payloads.extend([
                "; cat /etc/passwd",
                "| whoami",
                "&& id"
            ])
        
        return payloads
    
    def predict_next_steps(self, current_phase: str, findings: Dict[str, Any]) -> List[str]:
        """Predict optimal next steps based on current findings"""
        next_steps = []
        
        # Base next steps on current phase
        phase_transitions = {
            'reconnaissance': [
                'Perform detailed port scanning',
                'Enumerate discovered services',
                'Check for web applications'
            ],
            'scanning': [
                'Exploit high-severity vulnerabilities',
                'Test for authentication bypass',
                'Attempt privilege escalation'
            ],
            'exploitation': [
                'Establish persistence',
                'Enumerate local system',
                'Attempt lateral movement'
            ]
        }
        
        base_steps = phase_transitions.get(current_phase, ['Continue assessment'])
        next_steps.extend(base_steps)
        
        # Customize based on findings
        if findings.get('web_application'):
            next_steps.append('Perform comprehensive web application testing')
        
        if findings.get('high_severity_vulns', 0) > 0:
            next_steps.append('Prioritize exploitation of critical vulnerabilities')
        
        if findings.get('network_services'):
            next_steps.append('Test network service configurations')
        
        return next_steps
