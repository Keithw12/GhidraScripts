import java.util.List;
import java.util.ArrayList;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import ghidra.app.plugin.core.instructionsearch.InstructionSearchApi;
import ghidra.app.plugin.core.instructionsearch.model.MaskSettings;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.util.exception.InvalidInputException;

public class InstructionSearcherByRegex extends GhidraScript {
	@Override
	public void run() throws Exception {
		matchRegex();
	}
	@SuppressWarnings("unused")
		
	private void matchRegex() throws Exception {
		AddressSetView searchSet =
				currentSelection == null ? (AddressSetView) currentProgram.getMemory()
						: currentSelection;
		
		String regexstr = askString("Addresses to search by regex", "Please enter your regex:");
		Pattern pattern = Pattern.compile(regexstr);

		ArrayList<Address> matchingAddressList = new ArrayList<Address>();

		AddressRangeIterator iter = searchSet.getAddressRanges();

		boolean shouldContinue = true;
		monitor.setMessage("Searching all address of program or selection...");
		println("Searching all address of program or selection...");
		
		AddressIterator addrIter = searchSet.getAddresses(true);
		
		while (addrIter.hasNext() && !monitor.isCancelled() && shouldContinue/* && matcher.find()*/)
		{
			Address currentAddr = addrIter.next();
			println("currentAddr.toString():" + currentAddr.toString() + "");
			Matcher matcher = pattern.matcher(currentAddr.toString());
			if (matcher.find())
			{
				Address matchAddress = currentAddr;
				matchingAddressList.add(currentAddr);
				if (matchingAddressList.size() > 500) {
					popup("More than 500 matches found.");
					shouldContinue = false;
					break;
				}
			}
		}

		if (matchingAddressList.size() == 0) {
			println("No match found");
			return;
		}
	
		Address[] addrs = new Address[matchingAddressList.size()];
		matchingAddressList.toArray(addrs);
		show(addrs);
	}
}
