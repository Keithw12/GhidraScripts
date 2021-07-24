/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//
//Example script illustrating how to launch the Instruction Pattern Search dialog from a script.
//
//@category Search.InstructionPattern

import java.util.List;
import java.util.ArrayList;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import ghidra.app.plugin.core.instructionsearch.InstructionSearchApi;
import ghidra.app.plugin.core.instructionsearch.model.MaskSettings;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.util.exception.InvalidInputException;

/*
public class InstructionSearchScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		testLoadAddresses();
	}

	@SuppressWarnings("unused")
	private void testSearcher() {
		AddressFactory addressFactory = currentProgram.getAddressFactory();
		Address min = addressFactory.getAddress("140017291");
		Address max = addressFactory.getAddress("140017294");
		AddressSet addrSet = addressFactory.getAddressSet(min, max);

		InstructionSearchApi searcher = new InstructionSearchApi();

		// Search that masks out all operands.
		MaskSettings maskSettings = new MaskSettings(true, true, true);
		try {
			List<Address> results =
				searcher.search(currentProgram, addrSet.getFirstRange(), maskSettings);
			for (Address addr : results) {
				println(addr.toString());
			}

			// Search that masks nothing.
			results = searcher.search(currentProgram, addrSet.getFirstRange());
			for (Address addr : results) {
				println(addr.toString());
			}
		}
		catch (InvalidInputException e) {
			e.printStackTrace();
		}
	}

	@SuppressWarnings("unused")
	private void testLoadString() {
		InstructionSearchApi searcher = new InstructionSearchApi();

		String bytes = "10011011";
		searcher.loadInstructions(bytes, state.getTool());
	}

	private void testLoadAddresses() {
		InstructionSearchApi searcher = new InstructionSearchApi();

		AddressFactory addressFactory = currentProgram.getAddressFactory();
		Address min = addressFactory.getAddress("00400358");
		Address max = addressFactory.getAddress("0040036f");
		AddressSet addrSet = addressFactory.getAddressSet(min, max);

		searcher.loadInstructions(addrSet, state.getTool());
	}

}

public class SearchMemoryForStringsRegExScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		AddressSetView searchSet =
			currentSelection == null ? (AddressSetView) currentProgram.getMemory()
					: currentSelection;

		String regexstr = askString("Regular Expression", "Please enter your regex:");
		Pattern pattern = Pattern.compile(regexstr);

		ArrayList<Address> matchingAddressList = new ArrayList<Address>();

		AddressRangeIterator iter = searchSet.getAddressRanges();

		boolean shouldContinue = true;
		while (iter.hasNext() && !monitor.isCancelled() && shouldContinue) {
			AddressRange range = iter.next();
			monitor.setMessage("Searching ... " + range.getMinAddress() + " to " +
				range.getMaxAddress());

			byte[] bytes = new byte[(int) range.getLength()];
			currentProgram.getMemory().getBytes(range.getMinAddress(), bytes);

			String data = new String(bytes, "ISO-8859-1");
			Matcher matcher = pattern.matcher(data);

			while (!monitor.isCancelled() && matcher.find()) {
				int startIndex = matcher.start();

				Address matchAddress = range.getMinAddress().add(startIndex);
				matchingAddressList.add(matchAddress);

				if (matchingAddressList.size() > 500) {
					popup("More than 500 matches found.");
					shouldContinue = false;
					break;
				}

				if (matchAddress.compareTo(range.getMaxAddress()) >= 0) {
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
*/

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
		
		//byte[] bytes = new byte[(int) range.getLength()];
		//currentProgram.getMemory().getBytes(range.getMinAddress(), bytes);

		//String data = new String(bytes, "ISO-8859-1");
		
		AddressIterator addrIter = searchSet.getAddresses(true);
		
		while (addrIter.hasNext() && !monitor.isCancelled() && shouldContinue/* && matcher.find()*/)
		{
			Address currentAddr = addrIter.next();
			println("currentAddr.toString():" + currentAddr.toString() + "");
			Matcher matcher = pattern.matcher(currentAddr.toString());
			if (matcher.find())
			{
				//int startIndex = matcher.start();
				Address matchAddress = currentAddr;		//range.getMinAddress().add(startIndex);
				matchingAddressList.add(currentAddr);
				if (matchingAddressList.size() > 500) {
					popup("More than 500 matches found.");
					shouldContinue = false;
					break;
				}
				
				//if (matchAddress.compareTo(range.getMaxAddress()) >= 0) {
				//	break;
				//}
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

