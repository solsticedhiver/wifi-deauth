from impl import SingleClientDeauthAttack,\
                 MultipleClientDeauthAttack,\
                 GlobalDisassociationAttack


class WiFiDeauthAttackBuilder(object):
    
    @classmethod
    def build_from(cls, options):
        subclasses = WiFiDeauthAttackWrapper.__subclasses__()
        candidates = filter(lambda subclass: subclass.handles(options),
                            subclasses)
        return candidates[0](options)
        
        
class WiFiDeauthAttackWrapper(object):
    
    @classmethod
    def handles(cls, options):
        raise NotImplementedError
    
    def __init__(self, options):
        self.options = options
        
    def _get_attack_implementor(self):
        raise NotImplementedError        
        
    def run(self):
        attack = self._get_attack_implementor()
        return attack.run()
        
        
class SingleClientDeauthAttackWrapper(WiFiDeauthAttackWrapper):
    
    @classmethod
    def handles(cls, options):
        return len(options.client) > 0
    
    def _get_attack_implementor(self):
        interface = self.options.interface
        bssid = self.options.bssid
        client = self.options.client
        return SingleClientDeauthAttack(interface, bssid, client)
    
    
class GlobalDisassociationAttackWrapper(WiFiDeauthAttackWrapper):
    
    @classmethod
    def handles(cls, options):
        return len(options.client) == 0 and not options.should_sniff
    
    def _get_attack_implementor(self):
        interface = self.options.interface
        bssid = self.options.bssid
        return GlobalDisassociationAttack(interface, bssid)    
    
    
class MultipleClientDeauthAttackWrapper(WiFiDeauthAttackWrapper):
    
    @classmethod
    def handles(cls, options):
        return len(options.client) == 0 and options.should_sniff
    
    def _get_attack_implementor(self):
        interface = self.options.interface
        bssid = self.options.bssid
        timeout = self.options.timeout
        return MultipleClientDeauthAttack(interface, bssid, timeout)   