--The Ketje authenticated encryption scheme, designed by Guido Bertoni,
--Joan Daemen, Michaël Peeters, Gilles Van Assche and Ronny Van Keer.
--For more information, feedback or questions, please refer to our website:
--http://ketje.noekeon.org/

-- Implementation by the designers,
-- hereby denoted as "the implementer".

-- To the extent possible under law, the implementer has waived all copyright
-- and related or neighboring rights to the source code in this file.
-- http://creativecommons.org/publicdomain/zero/1.0/


library work;
	use work.ketjev2_globals.all;
	
library ieee;
use ieee.std_logic_1164.all;
use ieee.std_logic_arith.all;	


entity ketjev2_inversepi is

port (

    round_in     : in  k_state;
    round_out    : out k_state);

end ketjev2_inversepi;

architecture rtl of ketjev2_inversepi is


  ----------------------------------------------------------------------------
  -- Internal signal declarations
  ----------------------------------------------------------------------------

 
  signal inverse_pi_in,inverse_pi_out : k_state;
 
 
  
begin  -- Rtl




--connecitons


inverse_pi_in <= round_in;
round_out<=inverse_pi_out;

-- inverse pi
i7001: for y in 0 to 4 generate
	i7002: for x in 0 to 4 generate
		i7003: for i in 0 to N-1 generate
			--pi_out(y)(x)(i)<=pi_in((y +2*x) mod 5)(((4*y)+x) mod 5)(i);
			inverse_pi_out((1*x+0*y) mod 5)((1*x+3*y) mod 5)(i)<=inverse_pi_in(y) (x)(i);
		end generate;	
	end generate;
end generate;

end rtl;
