"""
CerbereAG startup banner.

Printed once per process — on MCP server startup, and on the first
AgentGuard() instantiation when running interactively. Set
AGENTGUARD_BANNER=false to disable (recommended in CI / production logs).
"""

import os
import sys

BANNER = r"""
                                                                                                   
                                                                                                   
                                                                                                   
                                                                 AA                                
                                                         A      AAAA                               
                                                        AAAA    AAAAA                              
                                                        AAAAA  AAAAAAAA                            
                                                         AAAAAAAAAAAAAAA                           
                                                      AAAAAAAAAAAAAAAAAAA                          
                                                    AAAAAAAAAAAAAAAAAAAAA                          
                                                   AAAAAAAAAAAAAAAAAAAA                            
                                          AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA                          
                                         AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA                         
                                          AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA                         
                                           AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA                         
                                             AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA                        
                                                 AAAAAAAAAAAAAAAAAAAAAAAAAA                        
                                                       AAAAAAAAAAAAAAAAAAAA                        
                                                         AAAAAAAAAAAAAAAAA                         
                                                          AAAAAAAAAAAAAAAAA                        
                                                         AAAAAAAAAAAAAAAAAA                        
                                                        AAAAAAAAAAAAAAAAAAAA                       
                                                       AAAAAAAAAAAAAAAAAAAAAAA                     
                                                     AAAAAAAAAAAAAAAAAAAAAAAAAA                    
                                                      AAAAAAAAAAAAAAAAAAAAAAAAA                    
                                                      AAAAAAAAAAAAAAAAAAAAAAAAA                    
                                                    AAAAAAAAAAAAAAAAAAAAAAAAAAAA                   
                                                   AAAAAAAAAAAAAAAAAAAAAAAAAAAAA                   
                                                 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA                   
                                               AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA                  
                                             AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA                  
                                            AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA                  
                                           AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA                   
                                          AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA                   
                                        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA                    
                                       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA                     
                                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA                      
                                    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA                      
                                  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA                      
                                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA                      
                               AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA                      
                              AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA                      
                             AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  AAAAAAA                      
                            AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  AAAAAAA                      
                            AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA    AAAAAAA                      
                           AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA     AAAAAA                      
                           AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA     AAAAAA                      
                           AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA     AAAAAA                      
                           AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  AAAAAAA     AAAAAA                      
                            AAAAAAAAAAAAAAAAAAAAAAAAAA     AAAAAAA      AAAAAA                     
           AA             AAAAAAAAAAAAAAAAAAAAAAAAAAA      AAAAAAA      AAAAAA                     
           AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA      AAAAAAA                    
            AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA      AAAAAAAAAAA               
                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA       AAAAAAAAAA              
         AAAAAAAAAAAAAAAAAAAAA AAAAAAAAAA  AAAAAAAAAA  AAAAAAAAAAAAAAAAAAAAAA   AAAAAAAAAAAA       
        AAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAA  AAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAA  AAAAAAAAAAAA       
        AAAAA     AAAAA        AAAA AAAAA  AAAAA AAAAA AAAAA       AAAAA  AAAAA AAAAA              
        AAAAA     AAAAAAAAA    AAAAAAAAAA  AAAAAAAAAAA AAAAAAAAA   AAAAAAAAAAAA AAAAAAAA           
        AAAAA     AAAAAAAAA    AAAAAAAAAA  AAAAAAAAAAAAAAAAAAAAA   AAAAAAAAAAA  AAAAAAAA           
        AAAAA     AAAAAAAAA    AAAAAAAAAA  AAAAAAAAAAAAAAAAAAAAA   AAAAAAAAAAA  AAAAAAAA           
        AAAAAAAAAAAAAAAAAAAAAA AAAA AAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAA AAAAAAAAAAAA       
        AAAAAAAAAAAAAAAAAAAAAA AAAA  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  AAAAA AAAAAAAAAAAA       
          AAAAAAAAAAAAAAAAAAAA AAAA   AAAAAAAAAAAAAAA  AAAAAAAAAAAAAAAAA   AAAAAAAAAAAAAAAAA       
                                                                                                                                       
                                                                                                   
     The Three-Headed Guardian of AI Agents
          Protect . Observe . Control
""".strip("\n")

_already_shown = False


def show_banner(force: bool = False) -> None:
    """Print the CerbereAG banner to stderr, once per process."""
    global _already_shown
    if _already_shown and not force:
        return
    if os.getenv("AGENTGUARD_BANNER", "true").lower() in ("false", "0", "no", "off"):
        return
    print(BANNER, file=sys.stderr)
    _already_shown = True

